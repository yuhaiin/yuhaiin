//go:build linux && lightweight_kernel

package lightweight

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	gvisortun "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// All TUN baselines use the same single-queue, no-VNET/no-offload file. Their
// client is Linux TCP in this process; CPU metrics include both client and stack.
// gVisor uses the production channel device adapter and CUBIC/SACK options.
// tun2socket uses its production NAT/Accept path with the same pre-opened file.
type benchmarkTun struct {
	*kernelIO
	mtu int
}

func (d *benchmarkTun) Read(bufs [][]byte, sizes []int) (int, error) {
	n, err := d.ReadPacket(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}
func (d *benchmarkTun) Write(bufs [][]byte) (int, error) {
	for i, b := range bufs {
		if err := d.WritePacket(b); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}
func (d *benchmarkTun) BatchSize() int   { return 1 }
func (d *benchmarkTun) Offset() int      { return 0 }
func (d *benchmarkTun) MTU() int         { return d.mtu }
func (d *benchmarkTun) GSOEnabled() bool { return false }

var _ netlink.Tun = (*benchmarkTun)(nil)

type benchmarkListener struct {
	ready chan net.Conn
	done  chan struct{}
	once  sync.Once
	stop  func()
}

func (l *benchmarkListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *benchmarkListener) Close() error   { l.once.Do(func() { close(l.done); l.stop() }); return nil }
func (l *benchmarkListener) Addr() net.Addr { return &net.TCPAddr{} }
func (l *benchmarkListener) deliver(c net.Conn) {
	select {
	case l.ready <- c:
	case <-l.done:
		_ = c.Close()
	}
}

func benchmarkStack(b *testing.B, kind string, mtu int) (net.Listener, func() Statistics) {
	b.Helper()
	raw := kernelLink(b, mtu)
	dev := &benchmarkTun{raw, mtu}
	l := &benchmarkListener{ready: make(chan net.Conn, 128), done: make(chan struct{})}
	switch kind {
	case "reno", "cubic", "bbr":
		s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}, MTU: mtu, CongestionControl: kind}, raw)
		if err != nil {
			b.Fatal(err)
		}
		listener, err := s.ListenTCP(netip.MustParseAddrPort("192.0.2.2:18080"))
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { _ = s.Close() })
		return listener, s.Stats
	case "gvisor":
		ep := gvisortun.NewEndpoint(dev)
		s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
		if e := s.CreateNIC(1, ep); e != nil {
			b.Fatal(e)
		}
		s.SetPromiscuousMode(1, true)
		s.SetSpoofing(1, true)
		s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
		cc := tcpip.CongestionControlOption("cubic")
		s.SetTransportProtocolOption(tcp.ProtocolNumber, &cc)
		sack := tcpip.TCPSACKEnabled(true)
		s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
		s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
			wq := new(waiter.Queue)
			e, err := r.CreateEndpoint(wq)
			r.Complete(err != nil)
			if err == nil {
				l.deliver(gonet.NewTCPConn(wq, e))
			}
		}).HandlePacket)
		l.stop = func() { ep.Close(); s.RemoveNIC(1); s.Destroy() }
	case "tun2socket":
		o := &device.Opt{Tun: device.TunConfig{MTU: int32(mtu)}, Options: &netlink.Options{MTU: mtu, Device: dev, Interface: netlink.TunScheme{Scheme: "fd"}, Inet4Address: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}, Inet6Address: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/64")}}}
		n, err := tun2socket.Start(o)
		if err != nil {
			_ = raw.Close()
			b.Fatal(err)
		}
		l.stop = func() { _ = dev.Close(); _ = n.Close() }
		go func() {
			for {
				c, err := n.Accept()
				if err != nil {
					return
				}
				l.deliver(c)
			}
		}()
	default:
		b.Fatalf("unknown benchmark stack %s", kind)
	}
	b.Cleanup(func() { _ = l.Close() })
	return l, func() Statistics { return Statistics{} }
}
func cpuSeconds() float64 {
	var r unix.Rusage
	if unix.Getrusage(unix.RUSAGE_SELF, &r) != nil {
		return 0
	}
	return float64(r.Utime.Sec+r.Stime.Sec) + float64(r.Utime.Usec+r.Stime.Usec)/1e6
}
func rssBytes() float64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	n, _ := strconv.ParseUint(fields[1], 10, 64)
	return float64(n * uint64(os.Getpagesize()))
}

func BenchmarkTUN(b *testing.B) {
	for _, kind := range []string{"gvisor", "tun2socket", "reno", "cubic", "bbr"} {
		for _, mtu := range []int{1280, 1500, 9000} {
			for _, flows := range []int{1, 8, 100} {
				for _, direction := range []string{"upload", "download"} {
					b.Run(fmt.Sprintf("%s/mtu=%d/flows=%d/%s", kind, mtu, flows, direction), func(b *testing.B) {
						l, stats := benchmarkStack(b, kind, mtu)
						defer l.Close()
						clients, servers := make([]net.Conn, flows), make([]net.Conn, flows)
						for i := range clients {
							ctx, cancel := context.WithTimeout(b.Context(), 5*time.Second)
							c, err := (&net.Dialer{}).DialContext(ctx, "tcp", "192.0.2.2:18080")
							cancel()
							if err != nil {
								b.Fatal(err)
							}
							clients[i] = c
							servers[i], err = l.Accept()
							if err != nil {
								b.Fatal(err)
							}
							_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
							_ = servers[i].SetDeadline(time.Now().Add(2 * time.Minute))
						}
						cpu := cpuSeconds()
						transferWorkload(b, clients, servers, 65536, direction)
						elapsedCPU := cpuSeconds() - cpu
						b.ReportMetric(elapsedCPU/(float64(b.N*65536*flows)/1e9), "CPU-s/GB")
						b.ReportMetric(rssBytes(), "RSS-B")
						st := stats()
						if kind != "gvisor" && kind != "tun2socket" {
							b.ReportMetric(float64(st.Retransmissions), "retransmits")
							b.ReportMetric(float64(st.Drops), "drops")
						}
						runtime.KeepAlive(stats)
					})
				}
			}
		}
	}
}
