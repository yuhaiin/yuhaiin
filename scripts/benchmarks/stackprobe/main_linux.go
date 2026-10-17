// stackprobe is an isolated TCP benchmark fixture, not a production SOCKS server.
// Its SOCKS endpoint accepts only 198.18.0.2:5201 and maps it to loopback iperf3.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/pprof"
	"sync"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweighttun"
	"golang.org/x/net/proxy"
	"golang.org/x/sys/unix"
)

func bridge(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	copyHalf := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}
	wg.Go(func() { copyHalf(a, b) })
	copyHalf(b, a)
	wg.Wait()
}

func serveSOCKS(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var header [4]byte
	if _, err := io.ReadFull(c, header[:2]); err != nil || header[0] != 5 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	if _, err := io.ReadFull(c, header[:]); err != nil || header != [4]byte{5, 1, 0, 1} {
		return
	}
	var addr [6]byte
	if _, err := io.ReadFull(c, addr[:]); err != nil || addr != [6]byte{198, 18, 0, 2, 20, 81} {
		return
	}
	u, err := net.DialTimeout("tcp4", "127.0.0.1:5201", 5*time.Second)
	if err != nil {
		return
	}
	defer u.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	bridge(c, u)
}

// The Android fixture transfers an actual VpnService fd with SCM_RIGHTS.
// The child runs as the ordinary app UID and never opens /dev/net/tun itself.
func receiveVPNFD(name string) (int, error) {
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: "@" + name, Net: "unix"})
	if err != nil {
		return -1, err
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, control := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	_, n, _, _, err := c.ReadMsgUnix(data, control)
	if err != nil {
		return -1, err
	}
	msgs, err := unix.ParseSocketControlMessage(control[:n])
	if err != nil {
		return -1, err
	}
	for _, msg := range msgs {
		fds, err := unix.ParseUnixRights(&msg)
		if err == nil && len(fds) == 1 {
			return fds[0], nil
		}
	}
	return -1, fmt.Errorf("missing VPN descriptor")
}

// Android's Java generator verifies the reverse direction independently.
func serveIntegrity(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	var header [9]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return
	}
	left := binary.BigEndian.Uint64(header[1:])
	if left > 1<<30 || header[0] > 1 {
		return
	}
	pattern := bytes.Repeat([]byte{0xa5}, 65536)
	buf := make([]byte, len(pattern))
	for left > 0 {
		n := min(left, uint64(len(pattern)))
		if header[0] == 0 {
			if _, err := io.ReadFull(c, buf[:n]); err != nil || !bytes.Equal(buf[:n], pattern[:n]) {
				log.Print("integrity read failed")
				return
			}
		} else if written, err := c.Write(pattern[:n]); err != nil || uint64(written) != n {
			log.Print("integrity write failed")
			return
		}
		left -= n
	}
	_, _ = c.Write([]byte{1})
}

func main() {
	mode := flag.String("mode", "stack", "stack, socks, or forward")
	fd := flag.Int("fd", -1, "inherited IP TUN fd (plain or VNET)")
	mtu := flag.Int("mtu", 1500, "TUN MTU")
	cc := flag.String("cc", "cubic", "congestion controller")
	profile := flag.String("cpuprofile", "", "CPU profile output")
	vpnSocket := flag.String("vpn-socket", "", "Android abstract socket carrying a VpnService fd")
	flag.Parse()
	if *vpnSocket != "" {
		var err error
		*fd, err = receiveVPNFD(*vpnSocket)
		if err != nil {
			log.Fatal(err)
		}
		ifr, err := unix.NewIfreq("")
		if err == nil {
			err = unix.IoctlIfreq(*fd, unix.TUNGETIFF, ifr)
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("ANDROID_TUN flags=0x%x uid=%d\n", ifr.Uint16(), os.Getuid())
		if context, err := os.ReadFile("/proc/self/attr/current"); err == nil {
			fmt.Printf("ANDROID_TUN selinux=%s\n", bytes.Trim(context, "\x00 \n\r\t"))
		}
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(*fd), unix.TUNSETOFFLOAD, 0)
		fmt.Printf("ANDROID_TUN TUNSETOFFLOAD(0)=%v\n", errno)
	}
	if *profile != "" {
		f, err := os.Create(*profile)
		if err != nil {
			log.Fatal(err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		defer pprof.StopCPUProfile()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var listener net.Listener
	var stack *lightweight.Stack
	var err error
	switch *mode {
	case "socks":
		listener, err = net.Listen("tcp4", "127.0.0.1:1080")
	case "forward":
		listener, err = net.Listen("tcp4", "127.0.0.1:5202")
	case "stack", "android-stack":
		native, openErr := device.OpenPacketWriter(netlink.TunScheme{Scheme: "fd", Name: "bench0", Fd: *fd}, *mtu)
		if openErr != nil {
			log.Fatal(openErr)
		}
		_ = unix.Close(*fd) // The production opener owns a duplicate.
		packetIO, adaptErr := lightweighttun.NewPacketIO(native)
		if adaptErr != nil {
			_ = native.Close()
			log.Fatal(adaptErr)
		}
		fmt.Printf("PACKET_IO headroom=%d gso=%v\n", native.Offset(), native.GSOEnabled())
		stack, err = lightweight.New(lightweight.Config{
			Addresses: []netip.Addr{netip.MustParseAddr("198.18.0.1")},
			MTU:       *mtu, CongestionControl: *cc, Promiscuous: true,
		}, packetIO)
		if err != nil {
			_ = packetIO.Close()
			log.Fatal(err)
		}
		defer stack.Close()
		listener, err = stack.ListenTCP(netip.AddrPort{})
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	fmt.Println("READY")
	for {
		c, err := listener.Accept()
		if err != nil {
			break
		}
		go func() {
			if *mode == "android-stack" {
				serveIntegrity(c)
				return
			}
			if *mode == "socks" {
				serveSOCKS(c)
				return
			}
			u, err := dialer.Dial("tcp4", "198.18.0.2:5201")
			if err != nil {
				log.Print(err)
				_ = c.Close()
				return
			}
			bridge(c, u)
		}()
	}
	if stack != nil {
		fmt.Fprintf(os.Stderr, "STATS %+v\n", stack.Stats())
	}
}
