# WireGuard inbound validation and benchmarks

Measured on 2026-10-18 against PR #561, starting at
`0414acba3ba8707504056b903efd82e5139bc5fc`.

## Test coverage

- Two concurrent, independently encrypted peers using a gVisor reference stack
  against the inbound lightweight stack, with preshared keys.
- IPv4 and IPv6 TCP echo of 264 KiB, including client half-close and complete
  response after FIN; UDP echo to intercepted destinations outside the VPN subnet.
- Authenticated endpoint roaming after reopening the client's UDP bind on a new
  port, without recreating the server or client IP stack.
- Packets with a source outside the peer's AllowedIPs do not reach the handler.
- Pending handshake response routing with a nonzero packet offset, pending entry
  expiry, rejection of unauthenticated endpoint changes, the pending table limit,
  concurrent peer updates, and cleanup.
- A regression test for uppercase hexadecimal peer endpoint keys. Previously,
  parsing accepted them but authenticated endpoint lookup used lowercase strings
  and failed to find the peer.

## Method

Linux amd64, AMD Ryzen 5 5600G, Go 1.27.2, GOAMD64=v1, CGO enabled, MTU 1420.
Both client and server use GOMAXPROCS=4. The server runs in a separate test
subprocess with its own Go scheduler; encrypted traffic crosses real loopback
UDP sockets. No system TUN, host routes, namespaces, or external VPN are required.

The UDP benchmark measures one outstanding echo request at a time, excluding the
initial handshake. TCP uses one established connection and transfers 256 KiB
per operation with a one-byte acknowledgement between blocks. Upload means
client to inbound; download means inbound to client. These measure the engine,
IP stack, and handler bridge, with an in-memory handler rather than a real
outbound proxy or WAN. UDP results are round-trip latency, not saturation
throughput. TCP results describe this single-connection workload, not a system
throughput ceiling.

The same benchmark source was compiled against the original PR head and the
modified code. Six pairs of one-second samples were run sequentially, alternating
which version ran first. Build, race tests, and lint were kept outside the final
measurement runs. Memory figures from the process-separated benchmarks cover
the client process only; use the bind microbenchmark to observe the server-side
allocation change. The harness reports server stack drops and retransmissions.

## Results

Medians of six samples; throughput uses decimal MB/s. The p-values are the
individual comparisons reported by `benchstat`.

| Measurement | Original PR | Optimized | Comparison |
| --- | ---: | ---: | --- |
| Authenticated endpoint learning | 88.41 ns/op | 16.40 ns/op | -81.45%, p=0.002 |
| Endpoint learning allocation | 128 B/op, 2 allocs/op | 0 B/op, 0 allocs/op | Eliminated |
| UDP echo, 64 bytes | 53.81 us | 53.24 us | No significant change, p=0.132 |
| UDP echo, 1200 bytes | 60.31 us | 59.37 us | No significant change, p=0.132 |
| TCP upload, 256 KiB blocks | 155.9 MB/s | 157.7 MB/s | +1.13%, p=0.041 |
| TCP download, 256 KiB blocks | 147.2 MB/s | 147.6 MB/s | No significant change, p=0.589 |

All final samples reported zero server stack drops and zero server TCP
retransmissions. The clear benefit is removing per-packet allocation and most
of the endpoint lookup CPU cost. The modest upload difference should not be
interpreted as a large end-to-end speedup. Server-side memory savings do not
appear in the client-only end-to-end allocation figures.

## Harness loss diagnosis

The harness's loopback client socket uses the production dialer's 7 MiB receive
buffer request. An initial run with the OS default buffer overflowed during TCP
downloads: Linux UDP RcvbufErrors increased and the server retransmitted TCP
segments. This produced second-long recovery stalls in both versions. Matching
the production buffer avoids measuring this harness-induced loss recovery.

## Optimization

The bind now indexes authenticated endpoints by the original `[32]byte` public
key. Previously, every authenticated received packet converted the public key
to a hexadecimal string while holding the bind mutex, allocating twice. Encoding
is now restricted to endpoint formatting and diagnostics. Endpoint learning,
locking, handshake routing, and expiry behavior otherwise follow the existing
implementation.

## Reproduction

```sh
GOMAXPROCS=4 go test ./pkg/net/proxy/wireguard -run '^$' \
  -bench 'Benchmark(ServerBindFromPeer|WireGuardInbound)' \
  -benchtime=1s -count=6 -cpu=4

go test -race ./pkg/net/proxy/wireguard/... \
  ./pkg/net/proxy/tun/lightweighttun/... ./pkg/inbound/... \
  ./pkg/contract/inbound/... -count=1 -timeout=2m
```

For a before/after comparison, copy `server_benchmark_test.go` into a checkout of
the original commit and compile each checkout with `go test -c`. Run the two
test binaries alternately with the benchmark flags above, using one sample per
invocation. The helper subprocess is started automatically.

Validation also passed `go build ./...`, the CI VPN outbound race-test package
set, `golangci-lint` v2.15.0 (`0 issues`), `go fix ./...` (no changes), gofmt,
and `git diff --check`.
