# Relay and sniff buffer lifetime

Idle response relays previously retained a relay buffer when the pipe was
wrapped by traffic accounting: `relay.Copy` recognized only `*pipe.Conn`.
Sniffed streams also retained their 16 KiB `bufio.Reader` until connection close,
even after forwarding all the pre-read bytes.

## Design

`netapi.BufferReader` describes the optional read capability that waits for data
before requesting a caller-owned buffer. Relay uses this interface, and the
statistics connection preserves it only when its underlying connection supports
it. Download accounting still counts bytes read, including a chunk followed by
a writer failure; connection registration and removal keep the original owner.
Ordinary TCP/TLS connections continue using the existing copy path.

Buffered relays allocate only when data arrives. After forwarding a chunk,
they keep their private buffer for 30–60 seconds of inactivity, so a brief pause
or shared-pool eviction does not force another allocation. The expiry callback
returns an idle buffer to the pool; the copy goroutine returns it immediately
when forwarding ends. Source copying and destination writing hold a lease, so
expiry cannot return storage while either side is using it. A mutex serializes
borrowing, expiry, and close. Activity sets a flag; only an expiry callback
reschedules the timer. This uses 30-second activity windows, avoiding per-chunk
clock reads and timer resets at the cost of conservative expiry timing.

`pool.NewBufferedConnSize` provides temporary pre-read buffering for sniffing.
After the prefix drains, the reader is reset and returned to its pool; subsequent
reads go directly to the connection. `BufioRead` can acquire another reader when
needed. The existing `NewBufioConnSize` constructor retains ongoing buffering
for protocols such as UDP over stream. Rewrapping the same connection preserves
ownership and can restore ongoing buffering.

`GetBufioReader` always returns an independently owned reader, even when its
input is a buffered connection. Returning the connection's internal reader
would create two owners: an external caller could pool it while the connection
still holds pre-read bytes, and another connection could overwrite those bytes.
Only `NewBufioConnSize`/`NewBufferedConnSize` reuse a connection's reader owner.
`NewBufioConn` transfers reader ownership to the connection. Temporary
`BufioRead` callbacks must not retain the reader or its byte slices.

This changes the old `GetBufioReader(bufferedConn, size)` aliasing behavior.
The returned reader still reads from the supplied connection, but its pre-read
bytes are private: direct connection reads cannot retrieve them. Code that
needs connection-visible pre-read bytes must use `NewBufioConnSize` and
`BufioRead`, or transfer an independently acquired reader with `NewBufioConn`.

Read, callback, release, and close share the same mutex. Close interrupts the
underlying read before acquiring that mutex. Parsing stays inside the sniff
callback so slices never outlive reader ownership. If a read supplies both data
and an error, releasing the drained reader saves the pending error for the next
read. Restoring a buffered callback seeds that error before invoking the callback,
including callbacks that only inspect `Buffered()`.

## Measurement

The baseline is commit `7cc972fd`; both revisions use identical benchmark
workloads. Measurements were taken on 2026-10-05 with Go 1.27.1, darwin/arm64,
Apple M4, and GOMAXPROCS=10. Throughput samples run for one second, six times,
without concurrent validation workloads. Compare medians with `benchstat`.

The idle benchmarks keep 128 connections or relays open across two garbage
collections and report the retained heap delta per connection. This custom metric
includes connection state and, for relays, goroutine and accounting state. It
measures retained heap rather than RSS or allocations per operation. GC and
cleanup are excluded from benchmark timing; use fixed iteration counts.

Commands:

```sh
go test ./pkg/statistics ./pkg/net/sniff ./pkg/net/proxy/http2/v2 ./pkg/metrics \
  -run '^$' \
  -bench '^(BenchmarkCountedPipeRelay|BenchmarkSniffStream|BenchmarkTunnelRoundTrip|BenchmarkObserveLatency)$' \
  -benchmem -benchtime=1s -count=6
go test ./pkg/statistics -run '^$' -bench '^BenchmarkCountedIdleRelays$' -benchtime=5x -count=6
go test ./pkg/net/sniff -run '^$' -bench '^BenchmarkSniffIdleConnections$' -benchtime=10x -count=6
go test ./pkg/net/proxy/http2/v2 -run '^$' -bench '^BenchmarkIdleTunnels$' -benchtime=3x -count=6
benchstat before.txt after.txt
```

Median results (six samples per revision):

| Workload | Baseline | Updated | Change |
| --- | ---: | ---: | ---: |
| Idle counted relay, retained heap | 19.78 KiB/relay | 3.80 KiB/relay | -80.77% |
| Drained sniff connection, retained heap | 16,600 B/connection | 152 B/connection | -99.08% |
| Sniff + forward 64 B | 271.8 ns/op | 243.5 ns/op | -10.39% |
| Sniff + forward 16 KiB | 680.5 ns/op | 586.5 ns/op | -13.81% |
| Sniff + forward 64 KiB | 1.703 us/op | 1.242 us/op | -27.04% |
| Sniff allocations, all three sizes | 13 allocs/op | 11 allocs/op | -15.38% |
| Counted pipe relay, 64 B | 611.1 ns/op | 613.6 ns/op | No significant change |
| Counted pipe relay, 16 KiB | 786.3 ns/op | 803.2 ns/op | No significant change |
| Counted pipe relay, 64 KiB | 3.231 us/op | 3.248 us/op | No significant change |

The retained-heap and sniff differences have p=0.002; counted relay timings
have p=0.240/0.132/0.615 and keep zero allocations per operation. Actual TCP
HTTP/2 round trips at 64 B/16 KiB/64 KiB show no significant latency change
(p=0.240/0.093/0.065), with the same 3/11/42 allocations. No HTTP/2 speedup is
claimed. The duration observations cost approximately 8.1 ns (TCP), 23.2 ns
(DNS), and 6.2 ns (route), with zero allocations.

Sniff timings and retained heap were rerun after the independent-reader
ownership fix. The retained heap remains approximately 152 B per connection
and allocations remain 11 per operation. Relay and HTTP/2 production copying
are unchanged by that ownership fix.

## Bursts and short-idle retention

The retained-heap and steady-throughput results above do not establish the
cost of repeated idle/activity transitions or mobile energy usage.
`BenchmarkCountedPipeBurstResume` compares the production counted relay with
the former lifetime-long buffer path by hiding the optional read capability.
The stream sends one setup chunk before measurement, then each operation sends
eight chunks. `WarmIdle` inserts 1 ms of inactivity before each burst. `AfterGC`
inserts two GCs while the relay is waiting for input, after the previous
destination write and lease release. Idle time and GC are excluded from timing
and allocation measurements. The benchmark checks a single connection's atomic
counter, avoiding an inconsistent snapshot across the aggregate cache's flush.

Go's pool expiry is driven by GC, not elapsed wall time. These two GCs happen
within the private cache's TTL. A separate `BenchmarkRelayBufferCacheResume`
simulates an activity-free expiry window, expires the buffer, and runs
two GCs before resuming. It models the cold-buffer state after long idle without
waiting a literal hour; neither benchmark measures phone wakeup or battery use.

The TTL comparison uses merged commit `8e793fda` as its production baseline,
with identical fixtures on both revisions. Six samples, 100 bursts each:

| Idle state / chunk size | Immediate return | Short retention | Allocations per burst before / after |
| --- | ---: | ---: | ---: |
| Warm idle / 1 KiB | 18.88 us | 18.07 us | 0 / 0 |
| Warm idle / 16 KiB | 25.77 us | 26.36 us | 0 / 0 |
| Two GCs / 1 KiB | 7.959 us | 6.939 us | 3 / 0 |
| Two GCs / 16 KiB | 10.95 us | 8.819 us | 3 / 0 |

After two GCs, allocated bytes fall from approximately 17.4 KiB per burst to
about 1 B per burst of incidental accounting work. Allocation counts are rounded
averages; the private-cache-only recent-idle benchmark reports exactly 0 B and
0 allocations. Burst timings have substantial variation, including a change
in the unchanged lifetime-retained control, so the allocation reduction is the
reliable result rather than a general burst-latency improvement.

After actual TTL expiry and two GCs, the cache-only benchmark still needs about
17.51 KiB and 5 allocations per resume, including a new timer. Short retention
reduces how often this cold state occurs; it cannot eliminate long-idle resume
allocation while also releasing the large buffer. A recently active flow keeps
its full configured relay buffer (normally 16 KiB) until the timeout. Initially
inactive flows still borrow no buffer and create no timer. Their measured heap
includes accounting, goroutine, and cache metadata; it remains approximately
4 KiB per relay, with no significant change in the paired idle measurement.

Final steady counted-relay medians for 64 B/16 KiB/64 KiB are
605.4 ns/798.4 ns/3.281 us, versus 608.6 ns/797.0 ns/3.230 us before retention;
none differs significantly (p=0.937/0.699/0.699). HTTP/2 final medians are
24.55 us/35.60 us/83.34 us. Before-change batches ranged from
24.28–25.31 us/35.38–38.45 us/83.02–101.20 us, depending on run order. The final
implementation shows no significant slowdown against the first baseline batch;
the later baseline batch is slower. This host variation prevents attributing
the apparent HTTP/2 speedup to the cache. HTTP/2 allocations remain 3/11/42.

Sniffing behaves differently: ordinary reads after draining the initial prefix
go directly to the connection and do not reacquire a reader on each burst.
`BenchmarkSniffResumeAfterPoolEviction` reports zero bytes and allocations for
both 1 KiB and 16 KiB resume reads, even after two GCs.

Expiry uses one-shot timers, with no new permanent goroutine per flow. Active
flows may reschedule expiry roughly every 30 seconds, and expiry itself is
additional work. Whether the reduced allocation/GC work outweighs timer work
and briefly retained heap for mobile energy requires measurements on the target
device under realistic traffic. Buffer sizes remain unchanged.

```sh
go test ./pkg/statistics ./pkg/net/sniff ./pkg/net/relay -run '^$' \
  -bench '^(BenchmarkCountedPipeBurstResume|BenchmarkSniffResumeAfterPoolEviction|BenchmarkRelayBufferCacheResume)$' \
  -benchmem -benchtime=100x -count=6
```

An experimental reduction of HTTP/2 request/response copy buffers from 16 KiB
to 8 KiB saved about 16 KiB per idle tunnel but increased 16 KiB/64 KiB round-trip
latency by 27%/58% and allocations from 11/42 to 20/83. That production change
was discarded; HTTP/2 buffer sizes remain unchanged. The real TCP tunnel
benchmarks remain as regression coverage.

## Latency metrics

TCP, DNS, and route metrics named `_seconds` previously received truncated
milliseconds. Their observation APIs now accept `time.Duration` and convert to
seconds inside the collector. TCP/DNS buckets now span 0.05–10 seconds; route
buckets start at 5 microseconds, preserving sub-millisecond measurements. The
existing TCP summary is retained and also records seconds.

Dashboards compensating for the old values with `/ 1000` must remove that
conversion. Explicit histogram `le` filters must use the new second-based
bounds. Historical samples have the old units; comparisons across rollout must
account for the change. External implementations of `metrics.Metrics` must
update the three duration method signatures to `time.Duration`.

## Validation boundary

Regression tests cover production accounting, payload integrity, EOF and
deadlines, short writes, pooled-buffer release on writer panic, pre-read prefix
preservation, close interrupting an active read, and data-plus-error delivery.
Additional concurrency checks cover 16 readers on one connection, 512 streams
sniffing and reusing readers concurrently, Close waiting for an active callback,
and a paused destination Write while its sender overwrites the acknowledged
source slice, closes, and 32 workers churn the shared buffer pool. Released
relay buffers are poisoned so premature release is observable even without
reuse. A deterministic regression reproduces prefix corruption through the
old `GetBufioReader` alias and verifies independent reader ownership.
Race checks cover both default and CGO SQLite release tags. Vet, Go fix, and
golangci-lint v2.14.0 are checked, along with Linux/Windows command builds.
Retention tests additionally cover real timer expiry and reactivation, activity
extending expiry, hundreds of concurrent expiry attempts during a paused Write,
and callbacks dispatched before close. A poisoning pool detects early or double
returns; the timer tests are repeated under the race detector.

The full suite on this macOS host fails `TestDial/prefer_ipv6` (unavailable IPv6
loopback targets) and NetworkManager `TestNM` (missing system D-Bus socket).
The pristine baseline reproduces both failures. Other packages pass.
These are local benchmark and regression results; the running service has not
been replaced, and they do not establish an end-to-end production speedup.
