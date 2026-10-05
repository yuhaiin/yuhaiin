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
| Sniff + forward 64 B | 271.8 ns/op | 239.2 ns/op | -11.98% |
| Sniff + forward 16 KiB | 680.5 ns/op | 559.8 ns/op | -17.74% |
| Sniff + forward 64 KiB | 1.703 us/op | 1.194 us/op | -29.92% |
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
Race checks cover both default and CGO SQLite release tags. Vet, Go fix, and
golangci-lint v2.14.0 are checked, along with Linux/Windows command builds.

The full suite on this macOS host fails `TestDial/prefer_ipv6` (unavailable IPv6
loopback targets) and NetworkManager `TestNM` (missing system D-Bus socket).
The pristine baseline reproduces both failures. Other packages pass.
These are local benchmark and regression results; the running service has not
been replaced, and they do not establish an end-to-end production speedup.
