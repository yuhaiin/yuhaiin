package yuubinsya

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

/*
Benchmark Results Summary (on Apple M4)
Small Packets (64 bytes):
No Coalesce: ~33 MB/s (1944 ns/op)
Coalesce: ~86 MB/s (743 ns/op)
Conclusion: Coalescing improves throughput by ~2.6x for small packets by reducing write overhead.
Latency (Single Packet):
No Coalesce: ~3.1 µs
Coalesce: ~4.2 µs
Conclusion: Coalescing adds ~1.1 µs of latency per packet due to channel and goroutine context switching.
This trade-off is typical: Coalescing significantly boosts throughput for small frequent packets at the cost of a microscopic increase in processing latency.
*/

func BenchmarkUoT_Throughput(b *testing.B) {
	sizes := []int{64, 512, 1400, 4096, 16384}
	modes := []struct {
		name     string
		coalesce bool
	}{
		{"NoCoalesce", false},
		{"Coalesce", true},
	}

	for _, size := range sizes {
		for _, mode := range modes {
			b.Run(fmt.Sprintf("%s_Size_%d", mode.name, size), func(b *testing.B) {
				client, server := net.Pipe()
				defer client.Close()
				defer server.Close()

				// Consumer
				go func() {
					buf := make([]byte, 32*1024)
					for {
						if _, err := server.Read(buf); err != nil {
							return
						}
					}
				}()

				pc := newPacketConn(pool.NewBufioConnSize(client, 4096), nil, mode.coalesce)
				defer pc.Close()

				payload := make([]byte, size)
				if _, err := io.ReadFull(rand.Reader, payload); err != nil {
					b.Fatal(err)
				}
				addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}

				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					if _, err := pc.WriteTo(payload, addr); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkUoT_Latency(b *testing.B) {
	modes := []struct {
		name     string
		coalesce bool
	}{
		{"NoCoalesce", false},
		{"Coalesce", true},
	}

	size := 64

	for _, mode := range modes {
		b.Run(mode.name, func(b *testing.B) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			received := make(chan struct{})

			// Consumer
			go func() {
				buf := make([]byte, 32*1024)
				for {
					if _, err := server.Read(buf); err != nil {
						return
					}
					// Signal that a read occurred.
					// Note: Since net.Pipe writes are matched one-to-one or blocked until fully consumed,
					// when Read returns, the data has been transferred.
					select {
					case received <- struct{}{}:
					case <-time.After(time.Second):
						// avoid leaking if benchmark stopped
						return
					}
				}
			}()

			pc := newPacketConn(pool.NewBufioConnSize(client, 4096), nil, mode.coalesce)
			defer pc.Close()

			payload := make([]byte, size)
			addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				if _, err := pc.WriteTo(payload, addr); err != nil {
					b.Fatal(err)
				}
				<-received
			}
		})
	}
}
