# Darwin route selection and snapshot refresh

Measured on 2026-11-05 with Go 1.27.3, darwin/arm64, Apple M4.
The baseline is commit `7aa8c71a91be13d81f6fc645b23db1019bda21b6`.

## Correctness findings

- Enabling CIDR `/0` matching exposed Darwin interface-scoped defaults as
  global routes. On the affected machine, the IPv6 proxy endpoint selected
  `utun4` instead of the unscoped default on `en0`. An IPv6 DNS query using
  the actual packet dialer timed out after two seconds before the fix and
  returned NOERROR in approximately 25 ms after filtering `RTF_IFSCOPE`.
  The running service was left on the user's rolled-back version.
- Gateway-only changes kept the previous route snapshot, even though the
  trie could be reused. Future identical refreshes repeatedly allocated
  two comparison maps. Updating the snapshot while reusing its holder
  preserves trie reuse and restores the allocation-free comparison path.
- With a default prefix present, invalid `net.IP` values matched the root.
  Reject invalid address lengths before insertion or lookup.

Regression coverage includes IPv4/IPv6 scoped defaults and host routes,
route-order independence, legitimate unscoped tunnel routes, scoped-only
fallbacks, snapshot metadata changes, trie replacement on interface changes,
zero-allocation stable refreshes, and invalid IP inputs.

## Component benchmarks

Three 300 ms samples per configuration. The route refresh benchmark uses
512 IPv4 prefixes: change the gateway once, then repeatedly reconcile the
unchanged new snapshot. Setup and initial trie construction are excluded.

| Component | Before | After |
| --- | --- | --- |
| Stable refresh after gateway change, median | 24,610 ns/op | 1,117 ns/op |
| Allocated bytes per stable refresh | 114,912 B/op | 0 B/op |
| Allocations per stable refresh | 9 allocs/op | 0 allocs/op |
| Existing parallel CIDR lookup, allocations | 0 B/op, 0 allocs/op | 0 B/op, 0 allocs/op |

The existing parallel lookup benchmark ranged from 3.86–4.41 ns/op before
and 4.12–5.30 ns/op after. These short parallel throughput samples do not
establish a single-query latency change.

Additional post-fix measurements:

| Component | Range across three samples | Allocation |
| --- | --- | --- |
| Darwin route snapshot acquisition | 54.1–57.3 us/op | approximately 35.8 kB/op, 182 allocs/op |
| Building a trie from 512 IPv4 prefixes | 21.8–23.0 us/op | 49,856 B/op, 1,038 allocs/op |

Snapshot acquisition includes interface enumeration and FetchRIB. The
parsed-RIB cache only avoids reparsing unchanged data; it does not eliminate
system queries or their allocations. Its benchmark depends on the host's
live routing table. Trie construction remains conditional on effective
prefix-to-interface mapping changes.

These are component CPU/allocation measurements, not process RSS, retained
heap, end-to-end throughput, or battery measurements. In particular,
`B/op` is allocated memory, not a measured leak or persistent footprint.

## Reproduction

```sh
go test ./pkg/net/dialer/interfaces ./pkg/net/trie/cidr -count=1
go test ./pkg/net/dialer/interfaces ./pkg/net/trie/cidr -run '^$' \
  -bench 'Benchmark(RouteSnapshotAfterGatewayChange|DarwinRoutes|RouterToTrie|CidrMatch_Search)$' \
  -benchmem -benchtime=300ms -count=3
```

The temporary live DNS probe was removed after the before/after experiment;
permanent regression tests do not depend on external DNS connectivity.
