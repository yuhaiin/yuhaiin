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

// Notify the benchmark after the previous destination write and buffer return
// have completed. This prevents a late Put from repopulating the pool during
// the idle GCs and hiding the first-resume allocation.
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
// AfterPoolEviction models resuming a long-idle stream whose pooled buffers
// were cleared by GC. It does not simulate a literal hour or device wakeup.
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
				idle = "AfterPoolEviction"
			}
			for _, size := range []int{1024, 16384} {
				b.Run(fmt.Sprintf("%s/%s/%d", mode, idle, size), func(b *testing.B) {
					sender, receiver := pipe.Pipe()
					raw := &burstPipe{Conn: receiver, waiting: make(chan struct{}, 1)}
					store, conn := countedTestConn(b, raw)
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
					if got := store.Cache.LoadRunningDownload(); got != uint64(b.N)*uint64(size*chunks) {
						b.Fatalf("download=%d", got)
					}
				})
			}
		}
	}
}
