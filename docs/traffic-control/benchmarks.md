# Traffic-control qualification and measurements

Measured on 2026-10-20, Linux/amd64, AMD Ryzen 5 5600G, Go 1.27.2-X:nodwarf5, `GOMAXPROCS=2`. Three one-second benchmark samples per case, medians below. Baseline and candidate run sequentially with no parallel tests/browser workload. The candidate includes the bounded buffer-cache / lock optimization in `bae05031`; merging main afterward changes no stack/trafficcontrol benchmark source.

Baseline is pre-traffic-control main `d0b4f280`; subsequent main `c3ac7d8e` does not change these benchmark paths. Candidate stack settings use the fair default; rate shaping is disabled for this stack comparison. This measures two in-memory lightweight stacks, one flow, MTU 1500, Reno for TCP. It is neither encrypted proxy throughput nor a WAN/native-device saturation test.

```sh
BASE_REF=d0b4f280 OUTPUT_DIR=/tmp/tc-bench scripts/traffic-control/benchmark.sh
# Defaults: GOMAXPROCS=2 BENCH_COUNT=3 BENCH_TIME=1s
```

| Workload | Main MB/s | Candidate MB/s | Throughput change | Main → candidate allocs/op |
| --- | ---: | ---: | ---: | ---: |
| UDP 64 B, 1 flow | 29.32 | 27.25 | -7.06% | 12 → 12 |
| UDP 1200 B, 1 flow | 373.15 | 357.38 | -4.23% | 12 → 12 |
| TCP 64 B upload | 8.02 | 7.57 | -5.61% | 2 → 2 |
| TCP 64 B download | 8.00 | 7.62 | -4.75% | 2 → 2 |
| TCP 64 KiB upload | 702.10 | 600.39 | -14.49% | 73 → 73 |
| TCP 64 KiB download | 707.30 | 597.46 | -15.53% | 73 → 73 |

All measured TCP cases report zero drops and zero retransmissions. The 64 KiB candidate uses about 70,456 allocation bytes/op versus 70,347 on main. Sparse classification avoids the original per-packet flow descriptor churn. Retaining bounded small queue slices and avoiding redundant nested locks improved the first candidate's roughly 560 MB/s bulk TCP to roughly 600 MB/s and returned allocation counts to main's level.

**The RFC's 5% overhead target is not met across these cases.** FQ-CoDel remains measurably more expensive than the old channel FIFO in this topology, especially for bulk TCP. This is an open rollout/performance consideration, not a passing acceptance item. `outputScheduler: "fifo"` is available for explicit deployment comparisons; none of the fair numbers above silently use FIFO. CPU profiling still shows scheduler enqueue/dequeue and clock work as meaningful cost. Further work should measure bounded batch dequeue and timestamp amortization without weakening fairness/ownership, then validate against real mixed traffic.

## Isolated engine cost

Current medians, same timed-run method:

| Case | ns/op | allocs/op |
| --- | ---: | ---: |
| Sparse FIFO output enqueue/dequeue | 38.27 | 0 |
| Sparse FQ-CoDel output enqueue/dequeue | 98.95 | 0 |
| 16 KiB ShapedWriter, unlimited | 204.4 | 0 |
| 16 KiB ShapedWriter, global cap | 248.2 | 0 |
| 16 KiB ShapedWriter, global + inbound + route | 342.4 | 0 |

ShapedWriter uses an `io.Discard` sink and a 1 TiB/s cap/1 GiB burst, deliberately above sink throughput to isolate policy, locking and chunk overhead. Its printed MB/s is not network throughput or a pacing-accuracy result. Actual low-rate upload/download pacing, live cap changes, concurrent aggregate admission, partial-write refunds, deadlines, cancellation and half-close are covered separately by tests.

## Qualification

- Full `go test ./...` and `go vet ./...`.
- Workflow-pinned golangci-lint v2.15.0; gofmt and a clean `go fix ./...` check.
- Race tests for trafficcontrol, relay, NAT, all TUN adapters, inbound, store, HTTP API and Hysteria2.
- Bounded classifier fuzzing (5 seconds, two workers, 89,026 executions on this run).
- Native Linux `lightweight_kernel` tests in an isolated user/network namespace against `/dev/net/tun`.
- Darwin/arm64, Windows/amd64, Android/arm64 package/test compilation with `CGO_ENABLED=0` and `-exec=true`; no native execution is claimed.
- Frontend typecheck, full tests, i18n/style audits, lint and build; real isolated Chrome with paired backend save/reload, >200 bindings, decimal editing, Select sentinel collision, discard and desktop/mobile screenshots.
- Separate standards/spec reviews; a rate-editing burst-reset defect was fixed and wrapped TCP half-close coverage added.

These checks establish the described ownership, policy and transport regressions and build compatibility. They do not establish authenticated-user fairness, p95/p99 latency under real QUIC/DNS/bulk saturation, CPU-flood isolation, physical-wire bandwidth caps or non-Linux native correctness. Those require capable devices and an external bottleneck workload.
