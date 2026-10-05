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

## Bursts and cold resume

The retained-heap and steady-throughput results above do not establish the
cost of repeated idle/activity transitions or mobile energy usage.
`BenchmarkCountedPipeBurstResume` compares the production counted relay with
the former lifetime-long buffer path by hiding the optional read capability.
Each operation sends eight chunks on the same open stream. `WarmIdle` inserts
1 ms of inactivity before each burst. `AfterPoolEviction` inserts two GCs while
the relay is waiting for input, after the previous buffer has been returned.
Idle time and GC are excluded from timing and allocation measurements.

Go's pool expiry is driven by GC, not elapsed wall time. Two GCs model the cold
buffer state after long idle with no intervening reuse; this is not a literal
one-hour idle test and does not measure a phone's wakeup or battery usage.

Six samples, 100 bursts each, on the same host:

| Idle state / chunk size | Retained buffer | Pooled buffer | Pooled allocations per burst |
| --- | ---: | ---: | ---: |
| Warm idle / 1 KiB | 18.15 us/burst | 19.66 us/burst | 103 B/burst median |
| Warm idle / 16 KiB | 23.75 us/burst | 19.78 us/burst | 17 B/burst median |
| Pool evicted / 1 KiB | 7.351 us/burst | 8.584 us/burst (+16.77%) | 17.55 KiB, 3 allocs |
| Pool evicted / 16 KiB | 9.021 us/burst | 10.450 us/burst (+15.85%) | 17.54 KiB, 3 allocs |

Warm-idle timing differences are not significant (p=0.093/0.132); the nonzero
allocated bytes reflect occasional pool misses even though Go rounds the
average allocation count to zero. Cold-resume timing increases are significant
(p=0.002), with about 1.2–1.4 us extra per eight-chunk burst. Cold allocations
include the buffer and pool bookkeeping. The retained path has no buffer
allocation during resume, at the cost of keeping 16 KiB throughout idle.

Sniffing behaves differently: ordinary reads after draining the initial prefix
go directly to the connection and do not reacquire a reader on each burst.
`BenchmarkSniffResumeAfterPoolEviction` reports zero bytes and allocations for
both 1 KiB and 16 KiB resume reads, even after two GCs.

No permanent small relay buffer or TTL is introduced here. A smaller copy
buffer must be evaluated against large transfers; a TTL adds cache ownership
and expiry behavior. The current implementation explicitly trades retained
idle heap for cold-resume allocation. Whether that trade saves mobile energy
requires measurements on the target device under realistic traffic and GC.

```sh
go test ./pkg/statistics ./pkg/net/sniff -run '^$' \
  -bench '^(BenchmarkCountedPipeBurstResume|BenchmarkSniffResumeAfterPoolEviction)$' \
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

The full suite on this macOS host fails `TestDial/prefer_ipv6` (unavailable IPv6
loopback targets) and NetworkManager `TestNM` (missing system D-Bus socket).
The pristine baseline reproduces both failures. Other packages pass.
These are local benchmark and regression results; the running service has not
been replaced, and they do not establish an end-to-end production speedup.
