# Traffic-control qualification and measurements

Measured on 2026-10-20, Linux/amd64, AMD Ryzen 5 5600G, Go 1.27.2-X:nodwarf5, `GOMAXPROCS=2`. Five one-second stack benchmark samples per case, medians below. Baseline and candidate run sequentially in separate `go test` processes with no parallel builds/tests/browser workload. Candidate source is `a127605e409c985aaccc1ffb1850916d5b93b2d9`.

Baseline is pre-traffic-control main `d0b4f280692d3d62b2ec16f268777f636b5bd841`; subsequent main `c3ac7d8e` does not change these benchmark paths. Candidate stack settings use the fair default; rate shaping is disabled for this stack comparison. This measures two in-memory lightweight stacks, one flow, MTU 1500, Reno for TCP. It is neither encrypted proxy throughput nor a WAN/native-device saturation test.

```sh
BASE_REF=d0b4f280 BENCH_COUNT=5 BENCH_TIME=1s OUTPUT_DIR=/tmp/tc-bench scripts/traffic-control/benchmark.sh
# Stack filters and sequential execution match the measurement above.
```

| Workload | Main MB/s | Candidate MB/s | Throughput change | Main → candidate allocs/op |
| --- | ---: | ---: | ---: | ---: |
| UDP 64 B, 1 flow | 29.23 | 28.35 | -3.01% | 12 → 12 |
| UDP 1200 B, 1 flow | 374.39 | 364.34 | -2.68% | 12 → 12 |
| TCP 64 B upload | 7.87 | 7.79 | -1.02% | 2 → 2 |
| TCP 64 B download | 7.86 | 7.80 | -0.76% | 2 → 2 |
| TCP 64 KiB upload | 706.85 | 661.40 | -6.43% | 73 → 73 |
| TCP 64 KiB download | 698.70 | 659.26 | -5.64% | 73 → 73 |

All measured TCP cases report zero drops and zero retransmissions. Allocation counts in the table are medians; one UDP 64 B candidate sample reports 13 allocs/op. Candidate 64 KiB allocation bytes/op are about 70,423–70,426 versus 70,347 on main. Individual current bulk TCP samples span 654.11–675.01 MB/s upload and 627.96–665.46 MB/s download; medians do not hide that variability.

The previous `93cf9c84` report (three one-second samples) measured UDP overhead of 4.23–7.06% and bulk TCP overhead of 14.49–15.53%. This follow-up reduces queue overhead through bounded batch dequeue, one monotonic timestamp/lock per dequeue batch, direct condition-variable readiness, active host/flow hints and shared already-validated admission. Readiness signals occur when service becomes available rather than for every packet. The single-packet device writer prefetches at most 32 already-queued packets without waiting to fill a batch. It retains DRR/AQM selection and releases any unwritten suffix on failure. Prefetch bounds, rather than eliminates, the service delay for a newly arriving host. Tests cover progress on the next batch, reader wakeups and close/admission ownership.

**The RFC's 5% overhead target is still not met across the measured cases.** Bulk TCP now trails main by about 6%, rather than about 15%. A shorter probe passed 5%, but the longer run above did not; the longer result is the acceptance evidence. `outputScheduler: "fifo"` remains an explicit comparison/rollback option; all fair numbers above use FQ-CoDel. Real mixed-traffic latency and external bottleneck measurements remain necessary before claiming rollout acceptance.

## Isolated engine cost

Current medians from three 500 ms samples, `GOMAXPROCS=2`:

| Case | ns/op | allocs/op |
| --- | ---: | ---: |
| Sparse FIFO output enqueue/dequeue | 40.71 | 0 |
| Sparse FQ-CoDel output enqueue/dequeue | 60.51 | 0 |
| Burst FIFO output, per packet (32-packet burst) | 41.42 | 0 |
| Burst FQ-CoDel output, per packet (32-packet burst) | 70.70 | 0 |
| 16 KiB ShapedWriter, unlimited | 203.4 | 0 |
| 16 KiB ShapedWriter, global cap | 246.6 | 0 |
| 16 KiB ShapedWriter, global + inbound + route | 340.9 | 0 |

The sparse fair queue previously cost 98.95 ns/op, measured with three one-second samples. Engine measurements isolate queue operations; they do not include stack scheduling, device I/O or contention across CPU cores.

```sh
GOMAXPROCS=2 go test ./pkg/net/trafficcontrol -run '^$' \
  -bench '^Benchmark(OutputQueue(Sparse|Burst)|ShaperWrite)$' \
  -benchtime=500ms -count=3 -benchmem
```

ShapedWriter uses an `io.Discard` sink and a 1 TiB/s cap/1 GiB burst, deliberately above sink throughput to isolate policy, locking and chunk overhead. Its printed MB/s is not network throughput or a pacing-accuracy result. Actual low-rate upload/download pacing, live cap changes, concurrent aggregate admission, partial-write refunds, deadlines, cancellation and half-close are covered separately by tests.

## Qualification

The performance follow-up reran full Go tests/vet, workflow-pinned lint, go fix/gofmt, trafficcontrol/lightweight races, native Linux TUN tests and the three cross-build targets. Regression coverage includes bounded batching and release, new-host progress, waiting-reader progress, FIFO close versus an in-flight admission, and zero/old public timestamps. Independent standards/spec reviews found no further actionable defect. CI additionally caught a Hysteria2 lifecycle-test race caused by swapping a live handler; the fixture now injects that handler before server startup, and the full Hysteria2 race suite passes. The earlier consolidated review also covered the broader integration and frontend checks listed below; frontend source was unchanged in this follow-up.


- Full `go test ./...` and `go vet ./...`.
- Workflow-pinned golangci-lint v2.15.0; gofmt and a clean `go fix ./...` check.
- Race tests for trafficcontrol, relay, NAT, all TUN adapters, inbound, store, HTTP API and Hysteria2.
- Bounded classifier fuzzing (5 seconds, two workers, 89,026 executions on this run).
- Native Linux `lightweight_kernel` tests in an isolated user/network namespace against `/dev/net/tun`.
- Darwin/arm64, Windows/amd64, Android/arm64 package/test compilation with `CGO_ENABLED=0` and `-exec=true`; no native execution is claimed.
- Frontend typecheck, full tests, i18n/style audits, lint and build; real isolated Chrome with paired backend save/reload, >200 bindings, decimal editing, Select sentinel collision, discard and desktop/mobile screenshots.
- Separate standards/spec reviews; a rate-editing burst-reset defect was fixed and wrapped TCP half-close coverage added.

These checks establish the described ownership, policy and transport regressions and build compatibility. They do not establish authenticated-user fairness, p95/p99 latency under real QUIC/DNS/bulk saturation, CPU-flood isolation, physical-wire bandwidth caps or non-Linux native correctness. Those require capable devices and an external bottleneck workload.
