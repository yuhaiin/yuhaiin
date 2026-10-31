package node

import (
	"net"
	"testing"
)

// The ordinary UDP path must retain zero allocation packet accounting when the
// optional context-aware probe writer is added.
func BenchmarkObservedPacketSend(b *testing.B) {
	c := &observedPacketConn{PacketConn: new(udpCircuitPacket), c: new(nodeCounters)}
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
	data := make([]byte, 64)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.WriteTo(data, addr); err != nil {
			b.Fatal(err)
		}
	}
}
