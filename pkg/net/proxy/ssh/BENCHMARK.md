# SSH validation and benchmarks

Measured on 2026-10-18 with Go 1.27.2, Linux amd64, and an AMD Ryzen 5 5600G.
The client uses GOMAXPROCS=4; the server runs in a separate process using its
default GOMAXPROCS. All traffic stays on loopback. The SSH server echoes channel
bytes directly; these throughput measurements exclude a destination TCP hop,
WAN latency, and packet loss. Separate functional tests cover real TCP
forwarding, DNS-over-TCP, and two nested SSH transports.

```sh
go test -race -count=3 -timeout=90s ./pkg/net/proxy/ssh/... ./pkg/contract/node ./pkg/register
go test ./pkg/net/proxy/ssh -run '^$' -bench '^BenchmarkSSH' -benchmem -benchtime=1s -count=3 -cpu=4 -timeout=120s
```

Each benchmark runs for one second, repeated three times. Results below are
medians. Echo MB/s counts the payload sent once per operation, although each
operation writes the payload and reads it back. Allocation counts cover the
client process only.

| Operation | Time/op | MB/s | B/op | Allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Cold authentication and channel open/close | 1.102 ms | — | 53,287 | 373 |
| Channel open/close on reused transport | 72.96 µs | — | 4,477 | 72 |
| Parallel channel open/close, four workers | 36.99 µs | — | 4,458 | 72 |
| TCP echo, 1 KiB | 20.63 µs | 49.64 | 0 | 0 |
| SSH echo, 1 KiB | 35.79 µs | 28.61 | 1,189 | 2 |
| TCP echo, 32 KiB | 26.13 µs | 1,254.24 | 0 | 0 |
| SSH echo, 32 KiB | 129.05 µs | 253.92 | 41,048 | 4 |
| TCP echo, 1 MiB | 224.12 µs | 4,678.67 | 0 | 0 |
| SSH echo, 1 MiB | 1.760 ms | 595.77 | 1,315,427 | 234 |

Transport reuse avoids roughly 93% of cold connection latency in this setup.
The original implementation at `1600e9d7` measured 69.10 µs per reused channel
and 672.86 MB/s for 1 MiB echo, but its channel connections did not support
deadlines. The deadline bridge adds two goroutines and two pooled 32 KiB
buffers per open channel. Its measured cost is approximately 6% higher reused
channel latency and 11% lower 1 MiB echo throughput in these separate runs.
These figures are observations on this host, not remote proxy capacity or a
statistical performance guarantee.

The bridge copies 32 KiB blocks to match SSH channel packets. Using the generic
16 KiB relay buffer initially reduced the 1 MiB echo result to about 378 MB/s;
matching the packet size recovered it to 592–600 MB/s across three runs.

Regression coverage includes:

- Independent read/write deadlines, deadline reset, and sibling channel
  isolation on a shared transport.
- Half-close draining without losing the final payload.
- Cancellation while waiting for another request's handshake, and shutdown
  during an incomplete handshake.
- An unanswered keepalive closing the transport after one reply interval.
- Host key selection with multiple advertised key types, including RSA-SHA2.
- Password and encrypted/unencrypted private-key authentication, TCP
  forwarding, DNS queries, nested SSH, concurrent channels, and reconnection.

The SSH race suite is also run by the `ssh-outbound-tests` CI job. Validation
for this change included repository-wide golangci-lint v2.15.0 (`0 issues`),
`go fix ./...` (no additional changes), and building `pkg/app` and `pkg/register`.
