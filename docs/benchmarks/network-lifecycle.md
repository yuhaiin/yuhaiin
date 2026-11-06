# Network lifecycle microbenchmarks

Measured on 2026-11-06, Linux amd64, Ryzen 5 5600G, Go 1.27.3, with the default
12-thread runtime. Baseline: `d63c2aa9` (main with DNS #672/#674). Implementation:
`cdc01817`. The same clean worktree ran the baseline and implementation in
sequence, after functional/race/static checks completed. No concurrent test or
cross-build process ran during these recorded samples.

| Benchmark | Baseline median | Implementation median | Implementation allocations |
| --- | ---: | ---: | ---: |
| Unchanged network snapshot / route notification | n/a | 61.22 ns | 0 B, 0 allocs |
| Register and unregister a known resource | n/a | 75.40 ns | 128 B, 1 alloc |
| Cached resolver `Raw` | 200.5 ns | 203.8 ns | 288 B, 4 allocs |
| Cached datagram behind a slow query | 5.171 us | 5.605 us | about 1429 B, 19 allocs |

The last benchmark uses 1000 iterations per sample because each iteration waits
one millisecond outside the timed section. Its ranges overlap (baseline
5.025–5.364 us; implementation 5.074–5.722 us). Raw cache-hit medians differ by
about 1.6%; the slow-query benchmark median differs by about 8.4%. These small
microbenchmarks are measurements, not a claim of an end-to-end performance win
or statistically established equivalence. Allocation counts are unchanged and
cache hits still do not enter the new lifecycle registry or upstream admission.

The unchanged-snapshot benchmark measures the already-collected snapshot
comparison and route-only classification, including the cached metric increment.
It excludes OS enumeration and route-cache acquisition. Registration measures
registry ownership, not a kernel dial. Neither is a packet-throughput benchmark.
There are no added route lookups, locks or lifecycle registrations on each packet.

Commands (three samples each):

```sh
go test ./pkg/net/netstate -run '^$' -bench . -benchmem -count=3
go test ./pkg/net/dns/resolver -run '^$' \
  -bench '^BenchmarkClientRawCached$' -benchmem -count=3
go test ./pkg/net/dns/server -run '^$' \
  -bench '^BenchmarkDNSCachedBehindSlowQuery$' -benchtime=1000x -benchmem -count=3
```

Raw data: [manager](data/network-lifecycle-2026-11-06/manager.txt),
[DNS baseline](data/network-lifecycle-2026-11-06/dns-cache-before.txt),
[DNS implementation](data/network-lifecycle-2026-11-06/dns-cache-after.txt),
[environment](data/network-lifecycle-2026-11-06/environment.txt).

## Executed validation

From a clean worktree at the implementation commit:

* `go test -p=4 ./...`
* `go fix -p=4 ./...` followed by `git diff --exit-code` (no generated edits)
* `go vet -p=4 ./...`
* `golangci-lint run --timeout=5m`, CI-pinned v2.15.0: zero issues
* `go test -race -p=4 ... -count=1` over netstate, dialer/interfaces, all DNS,
  NAT/netapi, direct, WireGuard, IKEv2, Hysteria2, MASQUE, Tailscale,
  GlobalProtect, OpenVPN, SoftEther, L2TP, node, inbound and cmd/android
* Windows amd64 and macOS arm64: `CGO_ENABLED=0 go build -p=4
  ./cmd/yuhaiin ./cmd/android` with the corresponding `GOOS`/`GOARCH`
* Android arm64: `CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -p=4 ./cmd/android`
* Android arm64/x86_64 AAR generated with gomobile, API 24
* Android companion: `./gradlew :app:lintDebug :app:testDebugUnitTest
  :app:assembleDebugAndroidTest`, using that local core AAR
* Formatting and whitespace checks

Build/test temporary files used a short disk-backed `TMPDIR`: this avoids the
host's constrained tmpfs and Unix-socket pathname limits. The original checkout
contains ignored local test programs with unresolved dependencies; clean-worktree
checks above include the entire tracked repository without altering those files.

See [network-lifecycle.md](../network-lifecycle.md) for platform/protocol coverage
and conservative unsupported cases. Physical network switching and live IKEv2
MOBIKE interoperability were not performed. Cross-builds and instrumentation APK
assembly are not device execution.
