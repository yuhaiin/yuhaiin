# Validation and benchmarks

Measured on Linux/amd64, AMD Ryzen 5 5600G, Go 1.27.2, with `GOMAXPROCS=2`.
These are local loopback/in-memory measurements in one Go test process per
scenario. They are not remote VPN/encrypted-outbound throughput claims.
The client, Gateway and synthetic upstream share the test process. HTTP payload
is 16 KiB; certificate handshakes use TLS over `net.Pipe` and a verified local CA.

| Benchmark | ns/op | B/op | allocs/op | Throughput |
| --- | ---: | ---: | ---: | ---: |
| Request context + synthetic A/B selection + warm pool lookup | 321.0 | 555 | 7 | — |
| 100 Path rules, match last | 1,058 | 0 | 0 | — |
| Disabled interception hook | 2.518 | 0 | 0 | — |
| HTTP/1 reverse proxy, complete request/response | 179,536 | 14,863 | 185 | 91.26 MB/s |
| HTTP/2 downstream reverse proxy | 229,239 | 15,660 | 190 | 71.47 MB/s |
| TLS handshake, issue a leaf each time | 801,021 | 149,716 | 1,276 | — |
| TLS handshake, cached leaf | 712,987 | 130,930 | 936 | — |
| Concurrent HTTP/2 reverse proxy | 134,949 | 15,636 | 189 | 121.41 MB/s |

Concurrent benchmark sampled up to 8,192 requests with Go benchmark parallelism
at two logical test workers: p50 **258.3 us**, p95 **347.0 us**. These latency
figures cover the whole local request. Both reverse-proxy benchmarks resolve an
outbound and borrow its transport on every request; their totals include that
selection and pool work. The isolated selection benchmark alternates synthetic
A/B callbacks and performs request context creation and warm transport lookup;
it excludes real Route matching, DNS and socket traffic. A separate HTTP/2 test uses distinguishable A/B mock
outbounds on the same downstream connection and changes a Selector while pools
already contain connections.

The common-handler TCP benchmark sends a 4 KiB echo and closes the connection.
WithoutHook and DisabledGateway were run in separate sequential processes, five
one-second repetitions each, to avoid competing event loops:

| Scenario | Median ns/op | Median B/op | allocs/op |
| --- | ---: | ---: | ---: |
| Existing handler without hook | 18,630 | 37,234 | 47 |
| Gateway installed, interception disabled | 19,660 | 37,249 | 47 |

The connection/goroutine benchmark is noisy: baseline repetitions ranged from
18,413 to 21,281 ns/op, and disabled repetitions from 19,407 to 19,788 ns/op.
It does not establish a stable 5.5% overhead or a speedup. The isolated disabled
branch is 2.518 ns/op with zero allocations; TCP lifecycle allocation count is
unchanged. No per-packet HTTP/TLS work is added, and UDP is untouched. Re-run on
the deployment host when evaluating end-to-end throughput or power use.

Reproduce:

```sh
GOMAXPROCS=2 go test ./pkg/gateway -run '^$' -bench . -benchmem -benchtime=1s
GOMAXPROCS=2 go test ./pkg/inbound -run '^$' \
  -bench 'BenchmarkGatewayDisabledTCPForwarding/WithoutHook$' -benchmem -benchtime=1s -count=5
GOMAXPROCS=2 go test ./pkg/inbound -run '^$' \
  -bench 'BenchmarkGatewayDisabledTCPForwarding/DisabledGateway$' -benchmem -benchtime=1s -count=5
go test -race -count=1 -timeout=180s \
  ./pkg/gateway ./pkg/cert ./pkg/net/proxy/http \
  ./pkg/net/proxy/tls ./pkg/inbound ./pkg/httpapi ./pkg/store ./pkg/storage/sqlite \
  ./pkg/route ./pkg/resolver ./pkg/statistics ./pkg/node ./pkg/app \
  ./pkg/contract/inbound ./pkg/contract/node
golangci-lint run --timeout=5m
go fix ./...
git diff --exit-code
```

Automated coverage includes HTTP policies/actions, isolated HTTP/2 outbound
selection/reuse, Selector changes, upstream certificate rejection, cancellation,
SSE, WebSocket, HTTP/2 gRPC frames/trailers, an 8 MiB response, HTTP interception,
MITM trust rejection, TLS passthrough/exclusion, lossless binary probes, CA
SAN/chain/expiry/cache coalescing, SQLite revision/reference transactions,
configuration rollback/concurrent updates, loop rejection and
pipelined CONNECT bytes, hot admission revocation, physical/upgraded listener
cleanup (including same-address owner replacement), no-SNI/IP, unsupported ALPN,
probe timeout/replay, and upstream client-certificate rejection without fallback. The workflow has an `http-gateway-tests` race job.

Actual process testing used a temporary database and local HTTP application:
reverse proxy, Path block 204, Rule tester, conflict 409, public-only CA status,
and restart persistence of the CA fingerprint/config all passed. Existing
privileged TUN/TProxy/Redir/WireGuard OS setup was not exercised by those tests.
Their TCP streams share the tested hook, but that is not a substitute for testing
platform permissions, routes and the actual client trust installation.

Frontend validation uses TypeScript, lint, translation checking, production build
and component tests, including saved edits, 409 draft retention, Rule tester and
explicit CA confirmation. Local Chrome testing also verified Gateway editing,
Rule tester, filters, CA confirmation and responsive layouts at desktop and
mobile viewport sizes. Real traffic through the browser-saved configuration
returned the local reverse-proxy response and an HTTP/2 204 for a blocked HTTPS
path. Physical mobile devices, OS trust installation and Spotify certificate
pinning remain outside this verification.

The initial GitHub race job exposed an existing GeoIP test assuming the user's
config directory already existed. Its fixture now uses a temporary data directory,
matching the other Route tests. A missed gofmt change in the inbound hook was also
corrected. `go build ./...` encounters pre-existing executable test directories
`cmd/test` and `pkg/net/proxy/tproxy/test` without `main`; the actual application
and CI target builds are checked separately. See [review](review.md) for findings
and [interception](interception.md) for the privileged local verification recipe.

## Route gate and early admission optimization

The existing L4 Routing editor now selects the Gateway before HTTP/TLS probing.
With no active Gateway routing action, the Route hook measured **2.516 ns/op,
0 B/op, 0 allocs/op** (median of three one-second repetitions).

The following admission-only comparison uses the same fixture against parent
`ad719ae1` and this change, in separate sequential processes on the machine above,
with three one-second repetitions per case:

| Rejected connection | Before median ns/op | After median ns/op | Before B/op / allocs | After B/op / allocs |
| --- | ---: | ---: | ---: | ---: |
| Known unrelated domain | 2,047 | 140.7 | 16,560 / 7 | 0 / 0 |
| Known excluded domain | 2,046 | 117.9 | 16,560 / 7 | 0 / 0 |
| Different inbound | 148.7 | 41.38 | 32 / 3 | 0 / 0 |
| Different destination port | 169.4 | 46.37 | 32 / 3 | 0 / 0 |

The fake connection returns EOF on its first Read. These figures measure probe
setup/buffer allocation and the avoided initial read attempt; they do not measure
network round trips or TLS handshake latency. Regression tests separately assert
that rejected known domains cause no read, wrapper or process lookup. A numeric
IP with no restored domain remains eligible for normal Host/SNI probing.

```sh
GOMAXPROCS=2 go test ./pkg/gateway -run '^$' \
  -bench '^BenchmarkAdmissionBypass$' -benchmem -benchtime=1s -count=3
GOMAXPROCS=2 go test ./pkg/route -run '^$' \
  -bench '^BenchmarkGatewayRouteGateDisabled$' -benchmem -benchtime=1s -count=3
```

The integration suite exercises the existing common inbound handler, persisted
L4 host-list rule, Gateway admission and actual downstream HTTP/TLS/HTTP2. It
also verifies an unrelated host and removal of the L4 Gateway rule preserve
ordinary forwarding while interception permissions remain configured.

A fresh application process and SQLite database also verified this wiring using
Mixed/CONNECT: the existing Routing RPC saved/applied a host-list Gateway action,
HTTPS `/ok` returned the local backend body with HTTP/2, `/ads/banner` returned
204 with HTTP/2, and an unmatched IP destination returned the unchanged backend
body. Only the two selected requests incremented Gateway request counters; an
untrusted client rejected its MITM certificate.

An imported Gateway whose sensitive policy was redacted rejects selected
connections while disabled. Its IDs are compiled into the immutable Gateway
snapshot, and ordinary configurations use a nil-map fast path. On a Ryzen 5
5600G, three warm local runs of `BenchmarkAdmissionBypass` with no guarded
Gateway measured 151.6–152.5 ns/op for a known-domain miss before the guard,
167.7–168.9 ns/op with a per-admission Gateway lookup, and 156.8–157.7 ns/op
with the snapshot fast path. All measured zero allocations. The synthetic
`BenchmarkAdmissionImportedGuard` measured 13.64–13.68 ns/op and zero
allocations for the guard lookup and a no-op test connection close. These are
in-process admission costs, not real network connection or close latency.

```sh
go test ./pkg/gateway -run '^$' -bench '^BenchmarkAdmission(Bypass|ImportedGuard)$' -benchmem -benchtime=1s -count=3
```
