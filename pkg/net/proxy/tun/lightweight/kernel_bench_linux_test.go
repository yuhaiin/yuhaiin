//go:build linux && lightweight_kernel

package lightweight

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	gvisortun "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
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

type ownedBenchmarkListener struct {
	net.Listener
	stack *Stack
}

func (l *ownedBenchmarkListener) Close() error { _ = l.Listener.Close(); return l.stack.Close() }

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
		return &ownedBenchmarkListener{listener, s}, s.Stats
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

// Each invocation is isolated in its own process by the runner. Heap and RSS
// deltas include the same 1000 Linux clients for every implementation; kernel
// socket memory is outside these process metrics (relevant for tun2socket).
func BenchmarkTUNIdle(b *testing.B) {
	for _, kind := range []string{"gvisor", "tun2socket", "reno", "cubic", "bbr"} {
		b.Run(kind, func(b *testing.B) {
			l, _ := benchmarkStack(b, kind, 1500)
			defer l.Close()
			debug.FreeOSMemory()
			var baseline runtime.MemStats
			runtime.ReadMemStats(&baseline)
			baselineRSS := rssBytes()
			baselineGoroutines := runtime.NumGoroutine()
			clients, servers := make([]net.Conn, 1000), make([]net.Conn, 1000)
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
			}
			for b.Loop() {
				debug.FreeOSMemory()
				var live runtime.MemStats
				runtime.ReadMemStats(&live)
				b.ReportMetric(float64(int64(live.HeapAlloc)-int64(baseline.HeapAlloc))/1000, "heap-per-conn-B")
				b.ReportMetric((rssBytes()-baselineRSS)/1000, "rss-per-conn-B")
				b.ReportMetric(float64(live.HeapAlloc), "idle-heap-live-B")
				b.ReportMetric(rssBytes(), "idle-RSS-B")
				b.ReportMetric(float64(runtime.NumGoroutine()-baselineGoroutines)/1000, "goroutines/conn")
				runtime.KeepAlive(clients)
				runtime.KeepAlive(servers)
			}
			for i, c := range clients {
				_ = c.Close()
				_ = servers[i].Close()
			}
			_ = l.Close()
			debug.FreeOSMemory()
			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			b.ReportMetric(float64(after.HeapAlloc), "closed-heap-live-B")
		})
	}
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
						if kind == "bbr" && os.Getenv("LIGHTWEIGHT_BBR_TRACE") == "1" {
							done := make(chan struct{})
							var traceWorkers sync.WaitGroup
							defer func() { close(done); traceWorkers.Wait() }()
							traceWorkers.Go(func() {
								ticker := time.NewTicker(100 * time.Millisecond)
								defer ticker.Stop()
								for {
									select {
									case <-done:
										return
									case <-ticker.C:
										c := servers[0].(*TCPConn)
										c.mu.Lock()
										snap := c.controller.(interface{ Snapshot() congestion.BBRSnapshot }).Snapshot()
										b.Logf("BBR diagnostic: v=%d mode=%s phase=%s bw=%d bwLo=%d inflightLo=%d inflightHi=%d pace=%d cwnd=%d flight=%d queued=%d delivered=%d lost=%d minRTT=%s round=%d", snap.Version, snap.Mode, snap.Phase, snap.Bandwidth, snap.BandwidthLo, snap.InflightLo, snap.InflightHi, c.controller.PacingRate(), c.controller.CongestionWindow(), c.flight(), c.txBytes, c.delivered, c.lost, snap.MinRTT, snap.Round)
										c.mu.Unlock()
									}
								}
							})
						}
						cpu, elapsedCPU := 0.0, 0.0
						transferWorkload(b, clients, servers, 65536, direction, func(start bool) {
							if start {
								cpu = cpuSeconds()
							} else {
								elapsedCPU = cpuSeconds() - cpu
							}
						})
						b.ReportMetric(elapsedCPU/(float64(b.N*65536*flows)/1e9), "CPU-s/GB")
						b.ReportMetric(rssBytes(), "RSS-B")
						var usage unix.Rusage
						if unix.Getrusage(unix.RUSAGE_SELF, &usage) == nil {
							b.ReportMetric(float64(usage.Maxrss)*1024, "RSS-peak-B")
						}
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
