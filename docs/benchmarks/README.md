# Benchmarks

This directory contains the **latest retained measurement snapshots**, not a performance claim about every subsequent commit. Implementation and integration behavior is documented in [Lightweight TCP/IP stack](../lightweight-tcpip-stack.md) and [Hysteria 2](../hysteria2.md). Benchmark results are tied to their recorded date, revision, host, topology and mode.

## Reports

| Report | Scope | Latest retained measurements |
| --- | --- | --- |
| [Lightweight TCP/IP](lightweight.md) | Native stack, hev/lwIP comparison, Linux TUN offload, native checksums, correctness limits | 2026-10-17 |
| [Full-cone UDP NAT](nat.md) | NAT cache/send microbenchmarks, queue round trips, full-cone correctness | 2026-10-18 |
| [FakeIP](fakeip.md) | SQLite mappings, leases, pool saturation and HTTPS rewriting | 2026-10-21 |
| [Protocol benchmarks](protocols.md) | Hysteria 2 interoperability/port hopping; OpenVPN real-server interop | 2026-10-07 to 2026-10-11 |

## Retained machine-readable data

The `data/` directory retains the summary datasets needed to inspect the documented comparisons. Values, metadata and test conditions in the lightweight summaries are unchanged from the original files:

| File | Original source / comparison |
| --- | --- |
| [hev-baseline.summary.json](data/hev-baseline.summary.json) | `lightweight-results/hev-20261017/ipv4-mtu1500.summary.json` (pre-optimization comparison) |
| [offload-before.summary.json](data/offload-before.summary.json) | `lightweight-results/optimization-20261017/before.summary.json` |
| [offload-after.summary.json](data/offload-after.summary.json) | `lightweight-results/optimization-20261017/after.summary.json` |
| [nat-fullcone.summary.json](data/nat-fullcone.summary.json) | Full-cone NAT before/after samples, revisions and fixture conditions |
| [fakeip.summary.json](data/fakeip.summary.json) | PR #598 before/after mapping, lease and exhaustion measurements |
| [checksum-native.summary.json](data/checksum-native.summary.json) | `lightweight-results/checksum-native-20261017/ab.summary.json` |

The full historical records, including intermediate stages, unsuccessful trials, JSONL samples, profiles, local device logs and protocol JSON, remain accessible through the repository's Git history. Removing a file here does **not** turn its old measurements into current benchmark results.

## Interpretation and maintenance

- **Do not compare unlike fixtures.** The native `go test`/TUN microbenchmarks and the independent-process `iperf3`/SOCKS/TUN tests measure different costs. Plain TUN, checksum offload, GSO/TSO, jumbo local MTU and physical VPN paths are not interchangeable.
- A before/after comparison is valid only when the original revisions, compiler, topology, affinities, stream counts and test windows are recorded. CPU s/GB and memory measurements need the same boundary.
- Short local-loopback measurements do not establish real WAN throughput, congestion fairness, long-tail latency, physical Android/macOS performance or encrypted VPN throughput.
- **Future experiments:** put disposable logs/pprof/JSONL under an ignored temporary or CI artifact directory, not `docs/benchmarks`. Commit a concise report and at most the final, comparable, machine-readable summaries. Update the existing topic report rather than adding another dated progress file. Rerun benchmarks after material code changes before labeling results current.
- To recover any deleted artifact: `git show <historical-commit>:docs/benchmarks/<old-path>`.

Benchmark harnesses remain in `scripts/benchmarks/`, `scripts/bench/hysteria2/` and `scripts/bench/openvpn/`. The reports contain their reproduction commands.
