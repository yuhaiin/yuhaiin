package nat

import (
	"context"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type benchmarkLeasedProxy struct{ benchmarkProxy }

func (benchmarkLeasedProxy) LeaseDestination(context.Context, netapi.Address) (func(), error) {
	return func() {}, nil
}

// Include the sender's lease-cache admission. BenchmarkNATCachedSend exercises
// write directly and intentionally excludes this step. No socket I/O or DNS.
func BenchmarkNATFakeIPCachedSend(b *testing.B) {
	dst, _ := netapi.ParseAddressPort("udp", "198.18.0.1", 443)
	real, _ := netapi.ParseAddressPort("udp", "192.0.2.1", 443)
	source := NewSourceChan(nil, benchmarkLeasedProxy{benchmarkProxy{target: real}})
	b.Cleanup(func() { _ = source.Close() })
	options := new(netapi.ResolverOptions)
	options.SetUdpSkipResolveTarget(true)
	source.contextCache = ContextCache{resolver: options}
	source.conn = &wrapConn{PacketConn: benchmarkPacketConn{}}
	pkt := netapi.NewPacket(dst, dst, pool.GetBytes(1200), netapi.WriteBackFunc(func(data []byte, _ net.Addr) (int, error) { return len(data), nil }))
	b.Cleanup(pkt.DecRef)
	if _, err := source.sendOneOwned(pkt, false); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := source.sendOneOwned(pkt, false); err != nil {
			b.Fatal(err)
		}
	}
}
