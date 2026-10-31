# Management security cost

Control-path measurements on Linux amd64, Ryzen 5 5600G (12 logical CPUs),
Go 1.27.3, three consecutive one-second samples on an otherwise idle host:

```
go test ./pkg/security/secret -run '^$' -bench '^BenchmarkSecretConfiguration$' -benchtime=1s -count=3 -benchmem
```

| Operation | Median time | Bytes/op | Allocs/op |
|---|---:|---:|---:|
| Clone and mask one node with one inline password | 22.081 µs | 12,651 | 172 |
| Resolve a preserved password for a metadata-only save | 23.970 µs | 10,547 | 172 |
| Clone and mask 1,024 nodes | 26.020 ms | 13,255,157 | 182,198 |

These are incremental configuration-processing costs. They exclude HTTP/JSON
response encoding, authentication, SQLite writes, durable audit authorization
and runtime activation. They are not forwarding benchmarks. The test constructs
one Shadowsocks layer per node; other protocol configurations can have different
sizes. Reflection and cloning intentionally allocate to avoid modifying shared
live configuration during reads. The snapshot revision uses a keyed HMAC over
private configuration; its digest is not a public password hash.

The identity/resource forwarding implementation and its Phase 2 throughput,
policy, admission and memory measurements remain documented in
[resources.md](resources.md). Secret processing is invoked on management
configuration reads/writes, not on the packet path. These measurements do not
establish WAN throughput, an end-to-end API service level, or a disk audit rate.

Raw samples: [secret-configuration.txt](data/security/secret-configuration.txt).

## Management authentication and durable audit

Measured on 2026-10-24, Linux amd64, Go 1.27.3, Ryzen 5 5600G (12 logical CPUs),
using private SQLite files in the host temporary directory. Run sequentially on
an otherwise idle test host, three samples with `-benchmem`. Baseline is phase 2
commit `bc052f6c`; the same API-compatible benchmark fixture was copied into a
clean archive of that commit. Current code includes custom roles, audit indexes,
10,000-row retention and `synchronous=FULL` for the private management database.
These are **control-plane operations**, not packet evaluation or network
throughput. Raw output: [before](data/security/management-before.txt) and
[after](data/security/management-after.txt).

| Operation (median) | Phase 2 | Phase 3 | Current bytes / allocations |
| --- | ---: | ---: | ---: |
| Local audit transaction, forwarding disabled | 65.333 µs | 198.821 µs | 5,030 B / 117 |
| Authenticate scoped administrator API token | 46.344 µs | 81.565 µs | 4,220 B / 97 |
| Audit plus outbox insert and simulated local acknowledgement | — | 238.638 µs | 8,015 B / 171 |

Audit fixtures seed 10,000 rows before timing. Baseline retains 1,000 rows under
its old fixed retention, current code retains 10,000. Baseline audit used 43
allocations/about 2,122 B and authentication used 54/about 2,296 B. The audit
transaction increases by about 133.5 µs (3.04×); it now includes more indexes,
metadata/settings, transactionally maintained retention counts and a synced
commit. Token authentication increases by about 35.2 µs (76%) for current custom
role inspection and metadata. Neither operation executes on ordinary forwarding.
This explicit cost buys stronger local audit durability and current owner/role
checking; it is not a general claim that enterprise management is free.

The outbox case uses the same seeded history and includes deleting its delivery
copy within the measured transaction to keep a steady bounded queue. It excludes
TLS, network latency, collector work and the asynchronous worker's separate ACK
transaction; it is not a SIEM throughput benchmark. There is no synchronous
external export on a management request or packet path.

An initial retention implementation scanned 10,000 rows on each insert. A
transactional row counter and oldest-row deletion reduced a sampled median from
291.360 µs to about 199 µs (roughly 32%). Retention tests cover large ID gaps,
manual expiration and queue/drop accounting. The final measurements still
include FULL sync and should be remeasured on deployment storage, especially
network or slow disks. FULL sync also applies to the existing private quota
worker's transactions; its durable credit batches remain off the packet path.

Reproduce from the repository root:

```sh
go test -run '^$' -bench '^BenchmarkManagement' -benchmem -count=3 ./pkg/management/auth
```

Existing forwarding, admission, large membership and 1,024-user memory/update
measurements are in [resources.md](resources.md). They measure the documented
fixtures (including in-memory quota accounting where specified), not physical
links or disk-backed SIEM delivery. Secret configuration reflection/copy costs
remain reported separately above.


## Configuration journal and workflow (2026-10-25)

Go 1.27.3, Linux amd64, Ryzen 5 5600G, one SQLite connection, FULL sync,
10,000 seeded security events, sequential idle runs, three 1-second samples.
This uses the same group owner mutator/schema for every row; `owner-only`
omits the optional workflow actor/journal. It is not an older binary or a
forwarding throughput comparison. Group members are empty; proxy membership
reload and listener/network work are excluded.

| Group edit path | Median time | Bytes/op | Allocations/op |
| --- | ---: | ---: | ---: |
| Owner mutator, audit, no workflow journal | 334.631 us | 9,381 | 213 |
| Managed direct edit, fresh authority and history | 602.772 us | 16,939 | 331 |
| Stage + explicit validation + commit | 1.855 ms | 71,149 | 1,397 |

Managed direct writes add about 268 us (80%) in this control-plane fixture,
including the additional current-authority query, canonical rollback documents,
diffs, history insertion and bounded retention in the same transaction. The
full staged workflow includes repeated owner validations and rollback-only
transactions plus durable draft creation. These paths do not run per packet,
stream read/write, or ordinary proxy authentication. Storage sync latency and
larger policy documents can dominate deployed performance. Forwarding and
large-user fixtures remain documented in [resources.md](resources.md).

Raw samples: [configuration-changes-linux-amd64.txt](data/security/configuration-changes-linux-amd64.txt).

```sh
go test ./pkg/management/auth -run '^$' -bench '^BenchmarkConfigurationGroupChange$' -benchtime=1s -count=3 -benchmem
```
