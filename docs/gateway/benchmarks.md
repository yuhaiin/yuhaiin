# Validation and benchmarks

Measured on Linux/amd64, AMD Ryzen 5 5600G, Go 1.27.2, with `GOMAXPROCS=2`.
These are local loopback/in-memory measurements in one Go test process per
scenario. They are not remote VPN/encrypted-outbound throughput claims.
The client, Gateway and synthetic upstream share the test process. HTTP payload
is 16 KiB; certificate handshakes use TLS over `net.Pipe` and a verified local CA.

| Benchmark | ns/op | B/op | allocs/op | Throughput |
| --- | ---: | ---: | ---: | ---: |
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
selection and pool work. A separate HTTP/2 test uses distinguishable A/B mock
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
  ./pkg/gateway ./pkg/cert ./pkg/net/proxy/reverse ./pkg/net/proxy/http \
  ./pkg/net/proxy/tls ./pkg/inbound ./pkg/httpapi ./pkg/store ./pkg/storage/sqlite \
  ./pkg/route ./pkg/resolver ./pkg/statistics ./pkg/node ./pkg/app
golangci-lint run --timeout=5m
go fix ./...
git diff --exit-code
```

Automated coverage includes HTTP policies/actions, isolated HTTP/2 outbound
selection/reuse, Selector changes, upstream certificate rejection, cancellation,
SSE, WebSocket, HTTP/2 gRPC frames/trailers, an 8 MiB response, HTTP interception,
MITM trust rejection, TLS passthrough/exclusion, lossless binary probes, CA
SAN/chain/expiry/cache coalescing, SQLite revision/reference transactions,
configuration rollback/concurrent updates, loop rejection, legacy adapters and
pipelined CONNECT bytes. The workflow has an `http-gateway-tests` race job.

Actual process testing used a temporary database and local HTTP application:
reverse proxy, Path block 204, Rule tester, conflict 409, public-only CA status,
and restart persistence of the CA fingerprint/config all passed. Existing
privileged TUN/TProxy/Redir/WireGuard OS setup was not exercised by those tests.
Their TCP streams share the tested hook, but that is not a substitute for testing
platform permissions, routes and the actual client trust installation.

Frontend validation uses TypeScript, lint, translation checking, production build
and component tests, including saved edits, 409 draft retention, Rule tester and
explicit CA confirmation. Browser rendering/screenshots were unavailable in this
execution environment; responsive layouts are implemented but visual browser
verification is a remaining manual check.
