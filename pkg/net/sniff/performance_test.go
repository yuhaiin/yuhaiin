package sniff

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type sniffTestConn struct {
	net.Conn
	reader *bytes.Reader
}

func (c *sniffTestConn) Read(b []byte) (int, error)      { return c.reader.Read(b) }
func (c *sniffTestConn) Close() error                    { return nil }
func (c *sniffTestConn) SetReadDeadline(time.Time) error { return nil }

func BenchmarkSniffStream(b *testing.B) {
	for _, size := range []int{64, 16384, 65536} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			payload := bytes.Repeat([]byte("x"), size)
			copy(payload, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
			s := New()
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				raw := &sniffTestConn{reader: bytes.NewReader(payload)}
				c := s.Stream(netapi.WithContext(b.Context()), raw)
				if n, err := io.Copy(io.Discard, c); err != nil || n != int64(len(payload)) {
					b.Fatalf("copy=%d/%v", n, err)
				}
				_ = c.Close()
			}
		})
	}
}

// Keep a drained batch alive across GC so the custom metric measures buffers
// retained by open idle connections, independently of the allocation rate.
// Use a fixed iteration count for this benchmark: each sample includes two GCs.
func BenchmarkSniffIdleConnections(b *testing.B) {
	const count = 128
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s := New()
	var retained uint64
	for b.Loop() {
		b.StopTimer()
		runtime.GC()
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		b.StartTimer()
		conns := make([]net.Conn, count)
		for i := range conns {
			raw := &sniffTestConn{reader: bytes.NewReader(payload)}
			conns[i] = s.Stream(netapi.WithContext(b.Context()), raw)
			if n, err := io.Copy(io.Discard, conns[i]); err != nil || n != int64(len(payload)) {
				b.Fatalf("copy=%d/%v", n, err)
			}
		}
		b.StopTimer()
		runtime.GC()
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		if after.HeapAlloc > before.HeapAlloc {
			retained += after.HeapAlloc - before.HeapAlloc
		}
		for _, c := range conns {
			_ = c.Close()
		}
		runtime.KeepAlive(conns)
		b.StartTimer()
	}
	b.ReportMetric(float64(retained)/float64(b.N*count), "retained-B/conn")
}

func TestSniffStreamPreservesReadAhead(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody")
	raw := &sniffTestConn{reader: bytes.NewReader(payload)}
	ctx := netapi.WithContext(t.Context())
	c := New().Stream(ctx, raw)
	defer c.Close()
	if ctx.GetHTTPHost() != "example.com" {
		t.Fatalf("host=%q", ctx.GetHTTPHost())
	}
	var got bytes.Buffer
	// Drain the prefix in tiny reads, including a zero-length read.
	if n, err := c.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read=%d/%v", n, err)
	}
	buf := make([]byte, 3)
	for {
		n, err := c.Read(buf)
		got.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("payload=%q", got.Bytes())
	}
}

func TestSniffStreamConcurrentBufferReuse(t *testing.T) {
	s := New()
	var workers sync.WaitGroup
	for worker := range 16 {
		workers.Go(func() {
			for iteration := range 32 {
				host := fmt.Sprintf("worker-%d-%d.example.com", worker, iteration)
				payload := bytes.Repeat([]byte{byte(worker + 1)}, 32781+iteration)
				copy(payload, "GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
				ctx := netapi.WithContext(t.Context())
				c := s.Stream(ctx, &sniffTestConn{reader: bytes.NewReader(payload)})
				got, err := io.ReadAll(c)
				// The drained reader is available to other workers even before
				// Close; retain ctx across another sniff to check parsed strings.
				other := s.Stream(netapi.WithContext(t.Context()), &sniffTestConn{
					reader: bytes.NewReader([]byte("GET / HTTP/1.1\r\nHost: overwritten.example.com\r\n\r\n")),
				})
				_ = other.Close()
				_ = c.Close()
				if err != nil || !bytes.Equal(got, payload) || ctx.GetHTTPHost() != host {
					t.Errorf("stream %d/%d corrupted: error=%v host=%q", worker, iteration, err, ctx.GetHTTPHost())
					return
				}
			}
		})
	}
	workers.Wait()
}
