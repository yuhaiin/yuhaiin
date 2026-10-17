# Experimental Darwin utun batching

Off by default. Pure Go (`CGO_ENABLED=0`), macOS arm64 and amd64. No
NetworkExtension, Skywalk, entitlement, new dependency, global sysctl, or default
route change. This experiment is **not ready to enable by default**.

## Enable and inspect

Open **Inbounds → edit the TUN → Advanced editor → macOS** in the WebUI.
Enable **Experimental packet batching**, then select the batch maximum and
pending packet limit and save. Saving recreates the TUN with those settings.
The controls appear only when the connected backend reports macOS; they are
per inbound, persisted with the configuration, and default to **off** for both
new and existing TUNs. No environment variable is needed.

The TUN protocol object's corresponding API fields are:

```json
{
  "darwin": {
    "experimentalBatch": true,
    "batchSize": 32,
    "pendingPackets": 32
  }
}
```

Both numeric options accept `1,16,32,64,128`. When enabled, a missing/zero
`batchSize` uses 32, and missing/zero `pendingPackets` uses the batch maximum.
With `experimentalBatch: false` or a missing `darwin` field, the original
single-packet path is retained. Invalid enabled options warn and safely keep
the native device. `32` is a trial setting, not an established optimum. Other
platforms preserve these settings but ignore them at runtime. Companion [WebUI PR 491](https://github.com/yuhaiin/yuhaiin-react/pull/491)
requires this backend version.

Only devices created by yuhaiin are eligible. External `fd://` devices keep their
existing ownership and I/O behavior. Before enabling, the adapter requires:

- A successful, deadline-bounded two-datagram UDP loopback **ABI smoke test**
  invoking both real syscalls. Only successful checks are cached; a temporary
  setup failure is retried for the next device. App Sandbox processes are excluded.
- A nonblocking utun descriptor and successful readback of
  `UTUN_OPT_ENABLE_NETIF == 0`. An unknown mode also disables the experiment.
- Successful setting and readback of the byte-limited pending-packet option.

Startup logs report the requested batch/depth, actual depth, `SO_RCVBUF` and `SO_SNDBUF`.
`interface { UTUNBatchStats() device.UTUNBatchStats }` on `netlink.Tun` provides a
live atomic snapshot; Close logs it. RX/TX counters include syscall attempts,
accepted/received messages, EAGAIN, EINTR, errors, native fallback calls, known
RX drops and uncertain TX packets. Counters are per device, not an end-to-end
loss metric. Average packets per **all attempts** is `Packets/Calls`; average
per successful call excludes EAGAIN, EINTR and errors from the denominator.

## API, ABI and data path

XNU's private `recvmsg_x` / `sendmsg_x` accept an array of `msghdr_x`. On both
LP64 architectures its size/alignment is 56/8 bytes, with offsets:

| Field | Offset | Size |
|---|---:|---:|
| name | 0 | 8 |
| namelen | 8 | 4 |
| iov | 16 | 8 |
| iovlen | 24 | 4 |
| control | 32 | 8 |
| controllen | 40 | 4 |
| flags | 44 | 4 |
| datalen | 48 | 8 |

The Darwin iovec is 16 bytes (pointer + 64-bit length). Padding, size and field
offsets have assertions/tests, including amd64 cross-compilation. Each message
has exactly one iovec containing **one** four-byte network-order AF_INET or
AF_INET6 header followed by one IP packet. `datalen` is receive output; all
non-iovec send fields are zero. No per-message destination or ancillary data is
used.

The syscall numbers 480/481 were checked against XNU `syscalls.master` and
x/sys's separate arm64/amd64 tables. Go's Darwin `syscall.Syscall6` supplies the
amd64 Unix trap class or arm64 SVC convention and runtime syscall transitions.
Do not use Go's internal libc-function-pointer calling convention with numeric
trap IDs. libSystem SPI wrappers are another approach used by reference
implementations; this experiment avoids a mandatory dynamic symbol import,
which could fail at process load before fallback is possible.

`MSG_DONTWAIT` and `syscall.RawConn.Read/Write` integrate with Go's poller.
EINTR retries; EAGAIN parks and does not disable batching. ENOBUFS propagates
normal pressure without permanently disabling batching. The owning `os.File`
keeps fd references valid through the callback and poll wait. Close marks the
adapter closed and closes the native device before joining I/O locks.
Cancellation follows the existing device Close contract. A stopped native event
stream switches back to the native reader to preserve its route-listener error
reporting.

Each direction owns reusable header/iovec arrays and a separate lock. Actual
pointers, escape analysis and `runtime.KeepAlive` protect synchronous kernel
borrows; buffer pointers are cleared on return. There is no per-packet metadata
allocation, new worker, extra receive copy on the normal path, aggregation
timer, or unbounded queue. A rare malformed-frame compaction may copy a valid
packet to an earlier slot.

The wrapper sits above the native single-packet device and reads directly into
the existing `netlink.Tun` packet buffers. gVisor already supplies packet lists
on write. The lightweight stack negotiates an optional `PacketBatchWriter`
**only with the Darwin experimental adapter**: its existing worker immediately
drains at most the configured number of already queued packets, retaining
leases until each accepted prefix completes. A single available packet is
sent immediately. Linux/Windows/Android do not negotiate the new capability;
their original single-packet/GSO loops remain in use. The legacy system-gVisor/tun2socket adapter also already supplies RX batches
and some write lists; its standalone UDP/ping replies remain individual calls.
No GSO support is claimed for Darwin. RX/TX capacity remains fixed after fallback, since callers already
allocated their arrays.

## Queue and failure semantics

`UTUN_OPT_MAX_PENDING_PACKETS = 16` is the **option number**, not a depth. XNU
initializes traditional utun's packet limit to one. Increasing it allows more
than one frame to wait on the control socket, but `SO_RCVBUF` independently
limits bytes. XNU's kernel-control enqueue can return ENOBUFS at that byte
limit; the pending count instead pauses interface output. Socket buffer limits
also depend on XNU's socket-buffer reservation limits.

The experiment does not enlarge buffers automatically. It reads the actual
`SO_RCVBUF` and caps the requested count to
`max(1, min(request, (SO_RCVBUF / 8 * 7) / (MTU + 4)))`, leaving byte headroom.
This is a conservative heuristic, not a guarantee of available depth or zero
loss. For example, a 512 KiB buffer permits 128 at MTU 1500 but only 50 at MTU
9000. The measured queue value is logged. Recreate the device after changing
MTU externally. Setup/readback failure safely retains native I/O; a readback
failure attempts to restore the old queue value. No queue-depth optimum has
been measured on a real utun here.

TX vectors also fit the measured `SO_SNDBUF` byte budget, using the largest
frame in a write to conservatively cap the count. Large MTUs can therefore
split a configured batch into several syscalls without risking an oversized
vector. Socket buffer sizes are not raised automatically.

A successful short send counts an accepted prefix; only the remaining suffix
is submitted again, under the same write lock. ENOSYS is known to occur before
dispatch, so it disables batching and sends the untouched suffix natively.
Other unexpected errors disable batching for the device; later independent
calls use the original device. The batch size does not shrink on fallback.

**Important unavoidable SPI limit:** XNU `sendmsg_x` suppresses certain pressure
errors after partial progress and returns a short count, but an unexpected
error can hide the accepted count. In particular, ENOSPC can follow accepted
packets. There is no per-message send completion output to recover it. Replaying
that call through `write` could duplicate packets. This implementation returns
the error and only the known prefix, records `TXUncertain`, and does **not**
replay the uncertain call. Delivery of that call cannot be guaranteed; the
upper stack may terminate or lose its unresolved suffix. This is a reason to
keep the feature experimental, not a promise of lossless fallback for arbitrary
kernel failures. The lightweight retry loop only retries recognized temporary
errors and its known unaccepted suffix.

The current yuhaiin wireguard-go constructor uses AF_SYSTEM/SOCK_DGRAM,
SYSPROTO_CONTROL and `com.apple.net.utun_control`, without enabling netif.
Nevertheless the runtime check is mandatory. sing-tun warns that netif's
`utun_pkt_input` can return ENOSPC without freeing the rejected mbuf after its
input queue fills, eventually causing device-wide network loss until reboot.
A fallback after seeing ENOSPC cannot undo a kernel mbuf leak. **Never enable
this on netif or borrowed NetworkExtension fds.**

Receive frames with bad AF/version, invalid IP length, short headers or
`MSG_TRUNC` are dropped and counted. If any valid frames remain, they are
delivered without an accompanying error (legacy tun2socket readers otherwise
discard the entire prefix); if none remain, recoverable ENOBUFS keeps readers
alive. On the tested XNU,
a truncated datagram can have `msg_flags == 0`; the IPv4 total length / IPv6
payload-length checks are necessary to avoid forwarding a truncated IP packet.
IPv6 jumbograms are unsupported. Unexpected receive errors may already have
consumed packets; fallback cannot reconstruct kernel-discarded data.

## Validation and measurements

Functional tests cover mixed IPv4/IPv6 frames, 1/16/32/64/128 batches, lengths
20 through 9000, boundaries/integrity/order, partial writes, pressure, missing
APIs, queue/mode setup failures, concurrent writers, Close, pointer retention,
unknown-error ambiguity and truncation without flags. Lightweight tests cover
FIFO queue draining, prefix retries, low-traffic immediacy and lease release.

```sh
CGO_ENABLED=0 go test ./pkg/net/proxy/tun/device
go test -race ./pkg/net/proxy/tun/{device,lightweight,lightweighttun,gvisor}
CGO_ENABLED=0 go test -run '^$' -bench BenchmarkUTUN -benchmem \
  -benchtime=300ms -count=5 ./pkg/net/proxy/tun/device
```

`BenchmarkUTUNSocketMicro` is a **connected UDP microbenchmark**, comparing
native file read/write with msgx carrying utun-shaped frames. Every path is
offered the same 128-packet burst; msgx splits it by its configured maximum.
`ns/op`, B/op and allocs/op refer to an entire offered burst; `ns/packet` is
normalized. It reports packets/s, Gbps, process CPU time/packet and CPU cores,
actual syscall attempts and average RX/TX batch, plus sampled **whole-burst**
p50/p95/p99 latency. These are not end-to-end packet latency percentiles.
Zero reported loss means every offered fixture datagram was drained before its
deadline; any missing datagram aborts that benchmark. The separate metadata
benchmark has no kernel I/O. Neither is a substitute for utun performance.

Real utun and end-to-end measurements remain unavailable without root and a
controlled peer. No speedup, CPU reduction, latency/loss or stability claim for
production TUN traffic follows from these microbenchmarks.

### Local microbenchmark results (2026-10-17)

Apple M4, Darwin 27.0.0 / XNU 13432.1.9, Go 1.27.2, darwin/arm64,
`CGO_ENABLED=0`, default GOMAXPROCS=10. Medians of five 300 ms samples,
with the same 128-packet offered burst for every path; no other validation
jobs from this experiment ran concurrently. Values below are **ns per packet**, not utun throughput.

| IP bytes | read/write | msgx 1 | msgx 16 | msgx 32 | msgx 64 | msgx 128 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 64 | 1975 | 2315 | 1413 | 1364 | 1440 | 1346 |
| 512 | 2042 | 2403 | 1467 | 1414 | 1418 | 1398 |
| 1400 | 2224 | 2529 | 1510 | 1446 | 1406 | 1509 |

All measured paths reported 0 B/op and 0 allocs/op (one op is 128 offered
packets). At batch 32, CPU time/packet changed from 2831/2927/3114 ns to
2004/2068/2091 ns for 64/512/1400 bytes respectively: about
29–33% less CPU/packet. Wall time/packet fell about
31–35%. Saturated process CPU cores
were not necessarily lower: the experiment processes more packets per second.

At batch 32, actual RX/TX averages were approximately 32/32; total syscall
attempts/packet were approximately 0.0625, versus 2.0 for read/write.
At batch 128, TX averaged 128 but RX averaged 87.3–98.9. Batch 1 was
slower than the original path. Larger supplied bursts show diminishing gains;
this does not select the optimum pending queue or justify a default change.

The [90 individual measurements](benchmarks/data/darwin-utun-socket-2026-10-17.csv)
include packets/s, Gbps, ns/op, allocation metrics, CPU cores/time, syscall
attempts, actual averages, sampled burst p50/p95/p99, and fixture loss.
Metadata-only tests also reported zero allocations. These short local runs
do not identify the dominant bottleneck in a real TUN pipeline: syscall
amortization helps this fixture, but kernel work, upper-stack copying, locks,
routing and encryption still require end-to-end profiling.

Validation: focused device/lightweight/lightweighttun/gVisor race tests passed;
golangci-lint **v2.15.0** passed for the affected Darwin TUN packages and for
the full repository with `GOOS=linux CGO_ENABLED=0`; `go fix -diff ./...`
was clean. Pure-Go full-repository builds passed for Darwin arm64/amd64,
Linux arm64/amd64, Windows amd64 and Android arm64; Darwin amd64 device and
adapter tests also cross-compiled. This does not constitute amd64 runtime testing.

Unfiltered local `go test ./...` failed on IPv6 loopback (`TestDial/prefer_ipv6`),
absent DBus (`TestNM`), and an unconfigured 127.0.0.2 alias (Hysteria2 address
hopping). The same failures were reproduced in an archived, unmodified main
checkout. They were not changed as part of this experiment. The full suite passes when
those four environment-dependent root tests are explicitly excluded. Full Darwin lint
also has four existing vpnkit/dataplane unused-code diagnostics; affected
Darwin TUN lint is clean. Hosted CI status is tracked in the PR.


### Opt-in real utun integration test (not ordinary CI)

Build the binary unprivileged, then run that binary with root privileges:

```sh
CGO_ENABLED=0 go test -c -o /tmp/yuhaiin-utun.test ./pkg/net/proxy/tun/device
sudo env YUHAIIN_RUN_UTUN_KERNEL=1 /tmp/yuhaiin-utun.test \
  -test.run '^TestUTUNKernelExperiment$' -test.v -test.timeout=10m
```

This bounded fixture creates temporary point-to-point test addresses
`192.0.2.1/peer .2` and `fd9c:3b2b:7a11::1/peer ::2`, and one explicit IPv6 peer
host route. It refuses local address collisions, leaves default routes/DNS
alone and removes its route/interface on cleanup. It checks native versus msgx,
MTU 1500/9000, IPv4/IPv6, 64/512/1400/MTU packet sizes, all batch maxima and
pending requests 16/32/64/128. It prequeues no more than the actual byte-limited
pending count, paces offered traffic at <=1000 pps and reflects UDP packets
through the kernel to check both directions. Reported RTT includes intentional
prequeue delay: this is a correctness/queue experiment, **not** a throughput
benchmark. It is skipped without both the explicit environment variable and
root, and is not executed by normal tests or CI. It has not been run as root in
this change's development environment.

### Separate end-to-end / high-load procedure (not executed)

Only on a disposable test Mac, after the bounded fixture succeeds and logs
positively confirm traditional utun, compare a baseline and each batch maximum
with the same MTU, IP family, peer, routing, encryption and payload workload.
Sweep pending requests independently (16/32/64/128), keeping the logged actual
byte limit. Use a controlled Linux/macOS peer with iperf3 and a working yuhaiin
route through the TUN; creating a UDP fixture is insufficient.

Start with a finite, low-rate run, e.g. on that already configured test network:

```sh
iperf3 -c "$PEER" -u -b 10M -l 64 -t 10 --json > run.json
/usr/bin/time -lp ./yuhaiin <its usual arguments>
```

Repeat for 512/1400 bytes and both directions (`-R`), then bounded TCP runs.
Never start with unlimited UDP TX or a continuous flood. Increase offered rate
only after checking loss, batch statistics and system health at each step;
stop on ENOSPC, TXUncertain or unexpected kernel errors. Capture per-device
stats, sender/receiver counts, process user+system CPU seconds, profiles, actual
syscall counts, and timestamped request/reply p50/p95/p99 under both sparse and
saturated traffic. iperf3 jitter is not packet-latency percentiles. Preserve
accepted prefixes when exercising pressure and compare protocol-level ordering.
High-load queue drops, p99 latency, sustained kernel stability and CPU/GiB
remain unmeasured here. No production default change is justified yet.

## Sources checked (2026-10-17)

- [Tailscale PR 21484](https://github.com/tailscale/tailscale/pull/21484),
  head `94884d27ff64eca999230bf8221208c99a2fe84d`: net/msgx ABI/raw traps and
  utun queue batching; [issue 21602](https://github.com/tailscale/tailscale/issues/21602)
  contrasts the libSystem approach and notes upper-stack batching effects.
- [sing-tun options](https://github.com/SagerNet/sing-tun/blob/9ffa5391a2adc292182ffbeac089e795b1a3190d/tun.go)
  and its Darwin configure function: netif ENOSPC warning and byte-limited queue.
- XNU `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`:
  [if_utun.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c),
  [if_utun.h](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.h),
  [socket_private.h](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/socket_private.h),
  [syscalls.master](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/syscalls.master),
  [uipc_syscalls.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_syscalls.c)
  (`sendmsg_x` error suppression, receive-list truncation), and kernel-control
  byte limits in `kern_control.c`.
- [Firezone June 2026 devlog](https://www.firezone.dev/devlog/2026-06): batching
  and ordering under backpressure. Its search-indexed text was available;
  direct retrieval returned HTTP 404 during research. Its reported performance
  is not a yuhaiin measurement and does not resolve the netif stability warning.

Implementation is limited to yuhaiin's needed frame I/O and its existing
adapters, rather than importing a third-party batching subsystem.
