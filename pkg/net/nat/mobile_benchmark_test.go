package nat

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type deadlineBenchmarkConn struct {
	*net.UDPConn
	updates atomic.Int64
}

func (c *deadlineBenchmarkConn) SetReadDeadline(deadline time.Time) error {
	c.updates.Add(1)
	return c.UDPConn.SetReadDeadline(deadline)
}

// Measure deadline updates on a real UDP socket, independently of send syscalls.
func BenchmarkMobileUDPReadDeadline(b *testing.B) {
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer socket.Close()
	counted := &deadlineBenchmarkConn{UDPConn: socket}
	conn := &wrapConn{PacketConn: counted}
	refresh := func() {
		if err := conn.SetReadDeadline(time.Now().Add(3 * time.Minute)); err != nil {
			b.Fatal(err)
		}
	}
	if throttled, ok := any(conn).(interface{ refreshReadDeadline(time.Duration) }); ok {
		refresh = func() { throttled.refreshReadDeadline(3 * time.Minute) }
	}
	b.ReportAllocs()
	for b.Loop() {
		refresh()
	}
	b.ReportMetric(float64(counted.updates.Load())/float64(b.N), "updates/op")
}
