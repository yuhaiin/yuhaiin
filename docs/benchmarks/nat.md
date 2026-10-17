# Full-cone UDP NAT

Measurement date: **2026-10-18**. Baseline: `f535076c`; candidate implementation: `d4be98a3`. These are dated Go microbenchmark results, not WAN or encrypted-proxy throughput measurements. The [retained summary](data/nat-fullcone.summary.json) records all five samples, allocations, revisions and fixture conditions.

## Behavior and ownership

The table continues to key a session by source or migration ID, never by destination. Every destination in that source session shares one outbound UDP socket; unsolicited packets from other remote endpoints remain accepted. Native UDP socket tests verify both properties.

The source owns admission, pending packets and a single reply writer. Socket readers own their connection and mapping generation. Forward and reverse mapping publication lives in `mapping.go`; bounded DNS scheduling lives in `resolve.go`. This prevents an old reader from consuming a replacement socket's reply notifications.

Reverse mappings are published **before** sending. A fast first reply and a successful retry after a failed first send therefore retain the original domain/FakeIP address. Rejecting one target no longer cancels the source. Cleanup shares the admission lock and accounts for queued, dialing and resolving work; admission retries a retired control.

After socket establishment, a slow local DNS lookup can queue that destination without blocking ready targets on the same socket. Up to four lookups per source run concurrently. Requests for the same destination share a lookup and preserve their send order. Pending DNS packets are bounded by `MaxUDPUnprocessedPackets`; shutdown cancels lookups and releases retained packet references. Results from a replaced mapping generation are reprocessed without reverting a newer inbound migration.

A resumed nonzero UOT migration ID preserves pinned addresses. A fresh non-migrating outbound socket gets new address caches. Comparable reply-writer identity distinguishes multiplexed streams even when their `RemoteAddr` is identical. Yuubinsya UOT implements the optional `ContextWriteBack` contract so source cancellation or migration can interrupt blocked socket/coalescing writes.

## Measurements

Linux amd64, AMD Ryzen 5 5600G, Go 1.27.2-X:nodwarf5, default `GOMAXPROCS=12`, no CPU affinity, five samples with Go's default benchmark duration. Both revisions use the same benchmark source.

Median **ns/op**, lower is better:

| Fixture | Before | After | Allocs/op | Time reduction |
| --- | ---: | ---: | ---: | ---: |
| Cached IP send | 200.70 | 52.65 | 2 → 0 | 73.8% |
| Cached rewritten IP send | 209.10 | 52.51 | 3 → 0 | 74.9% |
| Cached remote-domain send | 178.00 | 47.55 | 2 → 0 | 73.3% |
| 1200-byte in-memory round trip | 1629.00 | 1388.00 | 2 → 0 | 14.8% |

The new 4096-byte round-trip fixture completes without truncation at a median 1439 ns/op and zero allocations per operation. The baseline's default 2048-byte receive buffer cannot complete that fixture intact, so no speed ratio is reported for it.

`BenchmarkNATCachedSend` isolates warmed dispatch/address caching and send bookkeeping using a sink with no I/O. `BenchmarkNATRoundTrip` exercises table admission, both queues, the reader and writeback using an in-memory datagram peer and validates reply length. Its MB/s output counts one payload per operation, not both echo directions. These fixtures do not measure cold connection/DNS latency, kernel UDP throughput, concurrent-client scaling, physical devices or remote encryption.

## Limits and tradeoffs

- Each outbound reader uses one 64 KiB scratch buffer to read complete ordinary UDP datagrams. Queued replies use payload-sized pooled buffers, with one copy from scratch. Native UDP tests cover 1200-, 4096- and 60000-byte payloads. Other inbound/protocol adapters may impose their own limits.
- A mapping generation retains at most 1024 forward-cache entries and 1024 reverse endpoints. Uncached ordinary IP targets remain usable after the forward cache fills. New aliases requiring an additional reverse endpoint are rejected and counted as dropped when the reverse limit is reached; active reverse mappings are preserved.
- Two aliases of the same real endpoint remain ambiguous under full cone. The existing last-registered-alias policy is retained and tested.
- Arbitrary legacy `WriteBackFunc` callbacks cannot be forcibly interrupted. They must return or be interrupted by their owning inbound. The optional context contract is exercised by tests and adopted by UOT; the change does not create detached per-reply goroutines to hide blocked callbacks.

## Reproduction and validation

Candidate:

```sh
go test ./pkg/net/nat -run '^$' -bench 'BenchmarkNAT(CachedSend|RoundTrip)' -benchmem -count=5
```

To compare against the baseline, use an isolated checkout of `f535076c` and copy `pkg/net/nat/benchmark_test.go` from the candidate into it. Exclude the unsupported 4096-byte baseline case:

```sh
go test ./pkg/net/nat -run '^$' \
  -bench 'BenchmarkNAT(CachedSend|RoundTrip)/(IP|MappedIP|RemoteDomain|1200)$' \
  -benchmem -count=5
```

Validation completed with `go test ./...`, race tests for NAT/netapi/UOT and the related Hysteria integration, golangci-lint **v2.15.0** (`--timeout=5m`), `go fix ./...` with a clean diff, and whitespace/format checks. Twenty-one new NAT tests cover full cone, intact datagrams, mapping retries, rejection recovery, retirement, DNS ordering/concurrency/shutdown, stale results and reply migration; UOT tests cover cancellation of direct and coalesced writes. An earlier full-suite run intermittently timed out in HTTP/TLS compatibility tests; isolated checks and the final full-suite run passed. No HTTP implementation was changed.
