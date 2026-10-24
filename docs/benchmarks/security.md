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
