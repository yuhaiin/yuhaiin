package lightweight

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestTCPConcurrentReadersProgressAndClose(t *testing.T) {
	for _, mode := range []string{"data", "FIN", "RST", "Close"} {
		t.Run(mode, func(t *testing.T) {
			_, c, peer, seq := passiveWire(t, 100, 1000)
			type result struct {
				n     int
				value byte
				err   error
			}
			results := make(chan result, 2)
			for range 2 {
				go func() {
					var b [1]byte
					n, err := c.Read(b[:])
					results <- result{n, b[0], err}
				}()
			}
			var want error
			switch mode {
			case "data":
				_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 1000, nil, []byte("ab")))
			case "FIN":
				_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK|flagFIN, 1000, nil, nil))
				want = io.EOF
			case "RST":
				_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagRST, 1000, nil, nil))
				want = syscall.ECONNRESET
			case "Close":
				_ = c.Close()
				want = net.ErrClosed
			}
			seen := byte(0)
			for range 2 {
				select {
				case got := <-results:
					if !errors.Is(got.err, want) {
						t.Fatalf("read: %v, want %v", got.err, want)
					}
					if mode == "data" {
						if got.n != 1 {
							t.Fatal("reader did not consume one byte")
						}
						seen += got.value
					}
				case <-time.After(time.Second):
					t.Fatal("concurrent reader remained blocked")
				}
			}
			if mode == "data" && seen != 'a'+'b' {
				t.Fatal("readers lost or duplicated bytes")
			}
		})
	}
}
