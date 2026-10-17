//go:build darwin && !ios

package device

import (
	"fmt"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Microbenchmark ONLY: connected loopback UDP carrying utun-shaped frames.
// Both paths drain an offered burst before the next burst. This measures the
// adapter and syscall cost under supplied batching, not real utun or TCP speed.
func BenchmarkUTUNSocketMicro(b *testing.B) {
	for _, size := range []int{64, 512, 1400} {
		for _, batch := range []int{0, 1, 16, 32, 64, 128} {
			name := fmt.Sprintf("%d/read_write", size)
			if batch > 0 {
				name = fmt.Sprintf("%d/msgx_%d", size, batch)
			}
			b.Run(name, func(b *testing.B) {
				count := 128 // same offered burst for every path
				f, peer := udpSocketPair(b)
				// A benchmark can run longer than the functional fixture's deadline.
				if e := f.SetDeadline(time.Time{}); e != nil {
					b.Fatal(e)
				}
				if e := peer.SetDeadline(time.Time{}); e != nil {
					b.Fatal(e)
				}
				rc, e := f.SyscallConn()
				if e != nil {
					b.Fatal(e)
				}
				prc, e := peer.SyscallConn()
				if e != nil {
					b.Fatal(e)
				}
				native := &socketTun{f, 1500}
				d := newUTUNBatch(native, rc, max(batch, 1), socketSendBudget(b, rc))
				receiver := newUTUNBatch(&socketTun{peer, 1500}, prc, max(batch, 1), socketSendBudget(b, prc))
				sent, received := frames(count, size), frames(count, size)
				sizes := make([]int, count)
				samples := make([]int64, 0, 4096)
				sampleEvery := max(1, b.N/4096)
				var before, after unix.Rusage
				if e := unix.Getrusage(unix.RUSAGE_SELF, &before); e != nil {
					b.Fatal(e)
				}
				started := time.Now()
				b.SetBytes(int64(size * count))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					// Bound a stalled benchmark without per-iteration deadline syscalls.
					if i%16384 == 0 {
						deadline := time.Now().Add(5 * time.Second)
						if e := f.SetDeadline(deadline); e != nil {
							b.Fatal(e)
						}
						if e := peer.SetDeadline(deadline); e != nil {
							b.Fatal(e)
						}
					}
					var sample time.Time
					if i%sampleEvery == 0 && len(samples) < cap(samples) {
						sample = time.Now()
					}
					if batch == 0 {
						if n, e := native.Write(sent); n != count || e != nil {
							b.Fatal(n, e)
						}
						for j := range count {
							if n, e := peer.Read(received[j]); e != nil || n != size+4 {
								b.Fatal(n, e)
							}
						}
					} else {
						if n, e := d.Write(sent); n != count || e != nil {
							b.Fatal(n, e)
						}
						for got := 0; got < count; {
							n, e := receiver.Read(received[got:min(got+batch, count)], sizes[got:])
							if e != nil {
								b.Fatal(e)
							}
							got += n
						}
					}
					if !sample.IsZero() {
						samples = append(samples, time.Since(sample).Nanoseconds())
					}
				}
				b.StopTimer()
				elapsed := time.Since(started)
				if e := unix.Getrusage(unix.RUSAGE_SELF, &after); e != nil {
					b.Fatal(e)
				}
				// Check the final burst outside timing; functional tests check every one.
				for i := range sent {
					for j := range sent[i] {
						if sent[i][j] != received[i][j] {
							b.Fatal("datagram mismatch", i, j)
						}
					}
				}
				total := float64(b.N * count)
				b.ReportMetric(total/b.Elapsed().Seconds(), "packets/s")
				b.ReportMetric(total*float64(size)*8/b.Elapsed().Seconds()/1e9, "Gbps")
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/total, "ns/packet")
				calls := uint64(b.N * count * 2)
				txavg, rxavg := float64(1), float64(1)
				if batch > 0 {
					calls = d.tx.stats.calls.Load() + receiver.rx.stats.calls.Load()
					txavg = float64(d.tx.stats.packets.Load()) / float64(d.tx.stats.calls.Load())
					rxavg = float64(receiver.rx.stats.packets.Load()) / float64(receiver.rx.stats.calls.Load())
				}
				b.ReportMetric(float64(calls)/total, "syscalls/packet")
				b.ReportMetric(txavg, "TX-packets/syscall")
				b.ReportMetric(rxavg, "RX-packets/syscall")
				cpu := float64(after.Utime.Sec-before.Utime.Sec+after.Stime.Sec-before.Stime.Sec) + float64(after.Utime.Usec-before.Utime.Usec+after.Stime.Usec-before.Stime.Usec)/1e6
				b.ReportMetric(cpu/elapsed.Seconds(), "CPU-cores")
				b.ReportMetric(cpu*1e9/total, "CPU-ns/packet")
				b.ReportMetric(0, "loss-percent") // every offered datagram was synchronously drained
				slices.Sort(samples)
				for _, p := range []int{50, 95, 99} {
					b.ReportMetric(float64(samples[(len(samples)-1)*p/100]), fmt.Sprintf("burst-p%d-ns", p))
				}
			})
		}
	}
}

// Metadata and RawConn callbacks without kernel work: a lower bound on the
// adapter cost. This is intentionally separate from real-syscall measurements.
func BenchmarkUTUNBatchMetadata(b *testing.B) {
	for _, n := range []int{1, 16, 32, 64, 128} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			m := newMsgxIO(true)
			m.trap = func(_ uintptr, h []msgHdrX, _ bool) (int, syscall.Errno) { return len(h), 0 }
			rc := new(scriptedRawConn)
			bufs := frames(n, 1400)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if count, e := m.transfer(rc, bufs); count != n || e != nil {
					b.Fatal(count, e)
				}
			}
		})
	}
}
