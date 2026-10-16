//go:build linux && lightweight_kernel

package lightweight

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Run only in an isolated user/network namespace. Lack of capabilities is a
// failure of this explicitly selected suite, never an implicit passing skip.
type kernelIO struct{ file *os.File }

func (k *kernelIO) ReadPacket(b []byte) (int, error) { return k.file.Read(b) }
func (k *kernelIO) WritePacket(b []byte) error {
	n, err := k.file.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return err
}
func (k *kernelIO) Close() error { return k.file.Close() }
func kernelLink(t testing.TB, mtu int) *kernelIO {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	ifr, err := unix.NewIfreq("lwtest0")
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		t.Fatal("TUNSETIFF requires an isolated capable namespace:", err)
	}
	if err = unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	link := &kernelIO{os.NewFile(uintptr(fd), "lwtest0")}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"link", "set", "lwtest0", "mtu", fmt.Sprint(mtu), "txqueuelen", "10000", "up"}, {"addr", "add", "192.0.2.1/32", "dev", "lwtest0"}, {"-6", "addr", "add", "2001:db8::1/128", "dev", "lwtest0", "nodad"}, {"route", "add", "192.0.2.2/32", "dev", "lwtest0", "src", "192.0.2.1"}, {"-6", "route", "add", "2001:db8::2/128", "dev", "lwtest0", "src", "2001:db8::1"}} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			_ = link.Close()
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	return link
}
func kernelStack(t testing.TB, algorithm string) *Stack {
	t.Helper()
	link := kernelLink(t, 1500)
	s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")}, CongestionControl: algorithm}, link)
	if err != nil {
		_ = link.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func TestLinuxKernelTCP(t *testing.T) {
	for _, algorithm := range []string{"reno", "cubic", "bbr"} {
		for _, v6 := range []bool{false, true} {
			for _, direction := range []string{"inbound", "outbound"} {
				t.Run(fmt.Sprintf("%s/v6=%v/%s", algorithm, v6, direction), func(t *testing.T) {
					s := kernelStack(t, algorithm)
					host, guest := "192.0.2.1:18080", "192.0.2.2:18080"
					if v6 {
						host = "[2001:db8::1]:18080"
						guest = "[2001:db8::2]:18080"
					}
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					var l net.Listener
					var c net.Conn
					var err error
					if direction == "outbound" {
						l, err = net.Listen("tcp", host)
						if err == nil {
							c, err = s.DialContextTCP(ctx, netip.MustParseAddrPort(host))
						}
					} else {
						l, err = s.ListenTCP(netip.MustParseAddrPort(guest))
						if err == nil {
							c, err = (&net.Dialer{}).DialContext(ctx, "tcp", guest)
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					defer l.Close()
					defer c.Close()
					peer, err := l.Accept()
					if err != nil {
						t.Fatal(err)
					}
					defer peer.Close()
					_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					data := bytes.Repeat([]byte("kernel-independent-peer"), 32768)
					done := make(chan error, 1)
					go func() {
						buf := make([]byte, len(data))
						_, e := io.ReadFull(peer, buf)
						if e == nil && !bytes.Equal(data, buf) {
							e = ErrMalformed
						}
						if e == nil {
							_, e = peer.Write(buf)
						}
						if e == nil {
							e = peer.(interface{ CloseWrite() error }).CloseWrite()
						}
						done <- e
					}()
					if _, err = c.Write(data); err != nil {
						t.Fatal(err)
					}
					if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(c)
					if err != nil || !bytes.Equal(data, got) {
						t.Fatalf("kernel echo %d/%d: %v %+v", len(got), len(data), err, s.Stats())
					}
					if err = <-done; err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}
func TestLinuxKernelUDPAndICMP(t *testing.T) {
	s := kernelStack(t, "cubic")
	for _, v6 := range []bool{false, true} {
		host, guest := "192.0.2.1:18081", "192.0.2.2:18081"
		ping := "192.0.2.2"
		if v6 {
			host = "[2001:db8::1]:18081"
			guest = "[2001:db8::2]:18081"
			ping = "2001:db8::2"
		}
		u, err := s.ListenUDP(netip.MustParseAddrPort(guest))
		if err != nil {
			t.Fatal(err)
		}
		addr, err := net.ResolveUDPAddr("udp", host)
		if err != nil {
			t.Fatal(err)
		}
		kernel, err := net.ListenUDP("udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = u.SetDeadline(time.Now().Add(time.Second))
		_ = kernel.SetDeadline(time.Now().Add(time.Second))
		payload := bytes.Repeat([]byte{1, 2, 3, 4}, 1200)
		if _, err = kernel.WriteTo(payload, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(guest))); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 8192)
		n, from, err := u.ReadFrom(buf)
		if err != nil || !bytes.Equal(payload, buf[:n]) {
			t.Fatalf("kernel UDP/fragment inbound: %d %v", n, err)
		}
		if _, err = u.WriteTo(payload, from); err != nil {
			t.Fatal(err)
		}
		n, _, err = kernel.ReadFrom(buf)
		if err != nil || !bytes.Equal(payload, buf[:n]) {
			t.Fatalf("kernel UDP/fragment outbound: %d %v", n, err)
		}
		_ = u.Close()
		_ = kernel.Close()

		remote := netip.MustParseAddrPort(host)
		remote = netip.AddrPortFrom(remote.Addr(), 1)
		connected, err := s.DialUDP(netip.AddrPort{}, remote)
		if err != nil {
			t.Fatal(err)
		}
		_ = connected.SetReadDeadline(time.Now().Add(time.Second))
		if _, err = connected.Write([]byte("closed port")); err != nil {
			t.Fatal(err)
		}
		_, err = connected.Read(make([]byte, 1))
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("kernel UDP ICMP error association: %v", err)
		}
		_ = connected.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		out, err := exec.CommandContext(ctx, "ping", "-n", "-c", "1", "-W", "1", ping).CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("kernel ICMP echo: %v %s", err, out)
		}
	}
}
