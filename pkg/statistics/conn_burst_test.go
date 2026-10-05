package statistics

import (
	"fmt"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
)

// Notify the benchmark after the previous destination write and lease release
// have completed. For immediate-return relays, this prevents a late Put from
// repopulating the pool during the idle GCs and hiding resume allocations.
type burstPipe struct {
	*pipe.Conn
	waiting chan struct{}
}

func (p *burstPipe) Read(b []byte) (int, error) {
	p.waiting <- struct{}{}
	return p.Conn.Read(b)
}

func (p *burstPipe) ReadWithBuffer(get func() []byte) ([]byte, error) {
	p.waiting <- struct{}{}
	return p.Conn.ReadWithBuffer(get)
}

// WarmIdle models repeated small bursts separated by 1 ms of inactivity.
// AfterGC models resuming while the shared pools have been cleared by GC.
// The relay's private cache should survive GC while activity remains within
// its TTL. This does not simulate a literal hour or device wakeup.
// Idle time and GC are excluded from timings and allocation measurements.
// Each operation sends eight chunks through the production accounting wrapper.
func BenchmarkCountedPipeBurstResume(b *testing.B) {
	quietRelayBenchmarkLogs(b)
	for _, retain := range []bool{false, true} {
		mode := "Pooled"
		if retain {
			mode = "Retained"
		}
		for _, cold := range []bool{false, true} {
			idle := "WarmIdle"
			if cold {
				idle = "AfterGC"
			}
			for _, size := range []int{1024, 16384} {
				b.Run(fmt.Sprintf("%s/%s/%d", mode, idle, size), func(b *testing.B) {
					sender, receiver := pipe.Pipe()
					raw := &burstPipe{Conn: receiver, waiting: make(chan struct{}, 1)}
					store, conn := countedTestConn(b, raw)
					counter := countedConnectionCounter(b, store, conn)
					var src io.Reader = conn
					if retain {
						// Disable the optional capability to compare the former
						// lifetime-long buffer with the same Copy and accounting.
						src = relay.ReadOnlyReader{Reader: conn}
					}
					done := make(chan error, 1)
					stopped := make(chan struct{})
					go func() { defer close(stopped); _, err := relay.Copy(io.Discard, src); done <- err }()
					defer func() { _ = conn.Close(); _ = sender.Close(); <-stopped }()
					<-raw.waiting
					payload := make([]byte, size)
					// Activate the stream once before measuring resume costs.
					if _, err := sender.Write(payload); err != nil {
						b.Fatal(err)
					}
					<-raw.waiting
					const chunks = 8
					b.ReportAllocs()
					b.SetBytes(int64(size * chunks))
					for b.Loop() {
						b.StopTimer()
						if cold {
							runtime.GC()
							runtime.GC()
						} else {
							time.Sleep(time.Millisecond)
						}
						b.StartTimer()
						for range chunks {
							if _, err := sender.Write(payload); err != nil {
								b.Fatal(err)
							}
							<-raw.waiting
						}
					}
					_ = sender.CloseWrite()
					if err := <-done; err != nil {
						b.Fatal(err)
					}
					if got := counter.LoadDownload(); got != (uint64(b.N)*chunks+1)*uint64(size) {
						b.Fatalf("download=%d", got)
					}
				})
			}
		}
	}
}
