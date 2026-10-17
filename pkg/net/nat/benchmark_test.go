package nat

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type benchmarkPacketConn struct{ net.PacketConn }

func (benchmarkPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (benchmarkPacketConn) SetReadDeadline(time.Time) error           { return nil }

type benchmarkProxy struct {
	netapi.Proxy
	target netapi.Address
}

func (p benchmarkProxy) Dispatch(_ context.Context, a netapi.Address) (netapi.Address, error) {
	if p.target != nil {
		return p.target, nil
	}
	return a, nil
}

// These benchmarks isolate NAT dispatch, address caching and send bookkeeping.
// The sink performs no I/O; MB/s is payload processing capacity, not network bandwidth.
func BenchmarkNATCachedSend(b *testing.B) {
	for _, name := range []string{"IP", "MappedIP", "RemoteDomain"} {
		b.Run(name, func(b *testing.B) {
			dst, _ := netapi.ParseAddressPort("udp", "192.0.2.20", 443)
			proxy := benchmarkProxy{}
			switch name {
			case "MappedIP":
				proxy.target = dst
				dst, _ = netapi.ParseAddressPort("udp", "198.18.0.1", 443)
			case "RemoteDomain":
				dst, _ = netapi.ParseAddressPort("udp", "example.test", 443)
			}
			source := NewSourceChan(nil, proxy)
			b.Cleanup(func() { _ = source.Close() })
			options := new(netapi.ResolverOptions)
			options.SetUdpSkipResolveTarget(true)
			source.contextCache = ContextCache{resolver: options}
			pkt := netapi.NewPacket(dst, dst, pool.GetBytes(1200), netapi.WriteBackFunc(func(data []byte, _ net.Addr) (int, error) { return len(data), nil }))
			b.Cleanup(pkt.DecRef)
			conn := &wrapConn{PacketConn: benchmarkPacketConn{}}
			if err := source.write(b.Context(), pkt, conn); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(pkt.GetPayload())))
			for b.Loop() {
				if err := source.write(b.Context(), pkt, conn); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// A deterministic in-memory datagram peer exercises Table, both queues, reader
// and writeback. It excludes socket syscalls and does not model remote bandwidth.
type benchmarkEchoConn struct {
	packets   chan []byte
	done      chan struct{}
	closeOnce sync.Once
	addr      net.Addr
}

func (c *benchmarkEchoConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case c.packets <- b:
		return len(b), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}
func (c *benchmarkEchoConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case data := <-c.packets:
		return copy(b, data), c.addr, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}
func (c *benchmarkEchoConn) Close() error                   { c.closeOnce.Do(func() { close(c.done) }); return nil }
func (c *benchmarkEchoConn) LocalAddr() net.Addr            { return c.addr }
func (*benchmarkEchoConn) SetDeadline(time.Time) error      { return nil }
func (*benchmarkEchoConn) SetReadDeadline(time.Time) error  { return nil }
func (*benchmarkEchoConn) SetWriteDeadline(time.Time) error { return nil }

func BenchmarkNATRoundTrip(b *testing.B) {
	for _, size := range []int{1200, 4096} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			dst, _ := netapi.ParseAddressPort("udp", "192.0.2.20", 443)
			conn := &benchmarkEchoConn{packets: make(chan []byte, 1), done: make(chan struct{}), addr: dst}
			table := NewTable(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) { return conn, nil }})
			b.Cleanup(func() { _ = table.Close() })
			received := make(chan int, 1)
			pkt := netapi.NewPacket(dst, dst, pool.GetBytes(size), netapi.WriteBackFunc(func(data []byte, _ net.Addr) (int, error) { received <- len(data); return len(data), nil }))
			b.Cleanup(pkt.DecRef)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				if err := table.Write(b.Context(), pkt); err != nil {
					b.Fatal(err)
				}
				if n := <-received; n != size {
					b.Fatalf("truncated reply: %d of %d bytes", n, size)
				}
			}
		})
	}
}
