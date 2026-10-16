# Lightweight TCP/IP stack

Status: experimental opt-in implementation. Replacement readiness and the full
acceptance matrix are not established; measured results and gaps are explicit below.

The [BBR v3 and ownership report](benchmarks/lightweight-bbr-v3.md) records the
current controller, PMTU/recovery tests and performance work. The earlier
[transport checkpoint](benchmarks/lightweight-optimization.md) and original
benchmark matrix are historical measurements.

## Architecture and implementation plan

The independent `pkg/net/proxy/tun/lightweight` core owns IP packets, sockets,
TCP state and bounded protocol memory. It depends only on the Go standard
library. `lightweight/congestion` owns per-connection controllers. A separate
TUN adapter translates the existing device and Handler contracts. Existing
gVisor/tun2socket selection remains the default.

Implementation order:

1. Packet parsing/checksums, bounded reassembly, in-memory PacketIO tests, UDP
   and ICMP, with malformed-packet fuzzing.
2. Active/passive TCP, receive ordering, retransmission and socket lifecycle.
3. Independent Reno/HyStart++, CUBIC/HyStart++ and BBR v3 controllers with actual scheduled pacing.
4. Explicit opt-in JSON configuration and device/Handler adapter.
5. Reference-peer interoperability, race/leak/resource tests, benchmarks,
   platform builds and recorded results.

| Area | Required coverage | Verification boundary |
| --- | --- | --- |
| IPv4/IPv6 | validation, checksums, extension headers, fragments, MTU | IP packet parser and PacketIO |
| TCP | inbound/outbound, ordering, loss, windows, shutdown | net.Conn and independent reference peer |
| Congestion | Reno/CUBIC/BBR, registry, pacing | controller events and wire send timestamps |
| UDP/ICMP | both families, checksums, writeback/errors | sockets and independent reference packets |
| Resources | bounded queues/memory, cancellation, close races | socket/PacketIO lifecycle under race/goleak |
| Integration | absent config preserves existing path, DNS/FakeIP/routes | contract and TUN adapter |
| Performance | same-load baselines, repetitions, raw results | benchmark harness; offload separately identified |

Tests use the seams explicitly requested in the implementation brief: raw
packets, PacketIO, socket APIs, controller events and configuration. Timer
tests can use Go's `testing/synctest` virtual time without privileged TUN access.
Real kernel tests require a separate privileged environment; compilation alone
does not establish kernel interoperability or mobile runtime support.

## Reference review

The [Xray PR](https://github.com/XTLS/Xray-core/pull/7130) documents the pitfalls
of fixed receive windows on long RTT links, missing fragment reassembly, and
mixing offload gains with stack gains. The
[mipstack project](https://github.com/MetaCubeX/mipstack) is MPL-2.0 licensed.
No Xray or mipstack source is copied. Protocol sources include RFC 9293,
RFC 5681, RFC 6582, RFC 6298, RFC 7323, RFC 2018, RFC 8200, RFC 5722,
RFC 9438 and RFC 9406. The BBR v3 model adapts Google's
[2026-09-16 release](https://github.com/google/bbr/blob/674859761ded9f32690c7bdaf22ef585531452ed/net/ipv4/tcp_bbr3.c)
under its BSD-3-Clause option. Attribution and complete terms are in
[licenses/bbr-v3.md](../licenses/bbr-v3.md), also embedded in the binary's
existing license catalog. The remaining code retains the repository license.

## Modules, packet flow and sockets

`PacketIO` owns one reader and one writer. It transfers IP packets without a
link or virtio header; Close must interrupt both operations. The core owns its
read buffer. Parsing borrows that buffer only during synchronous dispatch.
Queued receive data, retransmission data and outbound packets each have their
own allocation. No asynchronous worker holds a caller's Write slice.

Inbound flow: PacketIO -> IP validation/reassembly -> transport validation ->
per-flow TCP lock or UDP socket queue -> application. Outbound flow: socket ->
bounded retransmission queue -> controller/window/pacing admission -> bounded
IP output queue -> PacketIO writer. There is no goroutine per segment. Idle
connections do not have goroutines or periodic timers by default.

The adapter lives in `pkg/net/proxy/tun/lightweighttun`, keeping device/netapi
(and their transitive gVisor dependencies) out of the core. It translates TCP
addresses to StreamMeta, UDP addresses to Packet/writeback, and marks gateway
and portal port 53 as DNS requests. Existing inbound DNS/FakeIP handling then
owns the request. TCP callbacks may block for the stream lifetime, so the
adapter dispatches them concurrently with an explicit 8192-handler bound.
Handlers must return when their stream closes; the adapter joins them on Close.

Core APIs:

```go
s, err := lightweight.New(lightweight.Config{
    Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
    CongestionControl: "cubic",
    Profile: lightweight.RemoteTunnel,
}, packetIO)
conn, err := s.DialContextTCP(ctx, netip.MustParseAddrPort("192.0.2.2:443"))
listener, err := s.ListenTCP(netip.MustParseAddrPort("192.0.2.1:8080"))
packetConn, err := s.ListenUDP(netip.MustParseAddrPort("192.0.2.1:5353"))
udp, err := s.DialUDP(netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.2:53"))
```

TCP implements net.Conn, CloseRead, CloseWrite and structurally implements
netapi.BufferReader. The latter borrows a caller buffer only after data is
ready, copies before freeing receive storage, and never retains that buffer.
UDP implements net.PacketConn and connected Read/Write. An unconnected socket
can send to multiple destinations. A zero TCP AddrPort is a transparent listener;
a specified TCP address requires a nonzero port. Dial chooses the first local
address of the matching family. This is a single-link L3 stack, with no ARP,
neighbor discovery, gateway resolution or Ethernet endpoint.

## TCP reliability and concurrency

The state machine covers SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1/2,
CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT and CLOSED; TCPListener is the LISTEN
boundary. It supports active/passive handshakes, half-close, simultaneous open
and close paths, duplicate SYN/FIN, exact-sequence RST with challenge ACKs,
cancellation and handshake/teardown timeouts. TIME-WAIT reserves the tuple for
120 seconds by default and restarts on a duplicate FIN.

Send/receive sequence arithmetic uses signed differences within bounded windows,
including wraparound. Receive overlaps use first-arrival bytes; duplicates do
not allocate more payload memory. Cumulative ACKs alone free send storage.
Validated SACK blocks credit newly delivered bytes once and remove those bytes
from the incremental flight count. Inferred lost transmissions leave the pipe;
repair packets re-enter it once. Multiple SACK-proven holes can be repaired in
one flight. RTO preserves useful SACK evidence. An advancing ACK stopping at a
SACKed head starts a short reneging confirmation interval, allowing reordered
ACKs to retire the head before discarding the scoreboard. Three duplicate ACKs
trigger fast retransmit of original data; partial recovery ACKs identify the
next original gap. RTT estimation uses SRTT/RTTVAR, Karn's
rule and RFC 6298's one-second minimum RTO with exponential backoff. Delayed ACKs
wait at most 20ms; reordering, FIN and window updates trigger immediate ACKs.
Zero-window probes do not consume new sequence space. Optional keepalive is
scheduled only when enabled and idle. ICMP PMTU feedback validates the quoted
TCP tuple and sent sequence before reducing MSS and splitting retained data.
Replacement pieces retain sequence/delivery/Karn history and explicitly request
resend. Old ACK/SACK feedback cannot classify a replacement as a new loss;
re-loss repair requires SACK evidence beyond its retransmission boundary.

Each connection owns a protocol mutex and a separate application Write mutex.
Close does not wait for the Write mutex and interrupts blocked reads/writes.
Flow lookup uses 32 short-held shard locks; protocol processing is not done under
a flow-table lock. Lock order is connection -> output waiter lock -> scheduler.
Flow removal can take a shard lock between the connection and output locks;
no shard-locked operation enters a connection. The scheduler releases its heap
lock before entering a connection. Fragment
processing has its own lock and never takes a connection lock.

## Congestion control and pacing

A controller receives byte-based sent/ACK/loss/timeout events; window sizes are
bytes, pacing rates bytes/second, and RTTs time.Duration. cwnd is independent of
peer receive window. TCP admits data against both windows and bytes in flight.
The delivery sampler records prior delivered/lost bytes, flight and send/ACK
intervals. Fresh SACK delivery is counted once; cumulative ACKs never credit it
again. Retransmissions carry fresh rate metadata while ambiguous RTTs still
obey Karn. App-limited bubbles persist until their delivery boundary is passed,
and intentional PROBE_RTT samples cannot lower the bandwidth maximum.

Reno supplies slow start, additive growth, fast recovery and timeout reduction.
CUBIC uses a time epoch, cubic origin/K, beta 0.7, fast convergence and a
Reno-friendly estimate. Both use RFC 9406 HyStart++: sequence-based rounds,
eight valid RTT samples, a 4–16ms delay threshold, quarter-rate Conservative
Slow Start and five CSS rounds. Lower RTTs can resume ordinary slow start.
Loss/timeout resets the estimator. BBR uses its own STARTUP and never HyStart++.

The name `bbr` selects v3 only; v1/v2 aliases are rejected. It includes v3's
UP/DOWN/CRUISE/REFILL phases, bandwidth/inflight lower and upper bounds,
loss-aware probe feedback, randomized/Reno-conscious probe timing, ACK
aggregation and aging min-RTT/PROBE_RTT. The model uses byte units and the
actual PacketIO sender batch budget rather than Linux's packet/TSO units.
Snapshot exposes version, mode, phase, bounds and round state. This adaptation
does not claim Linux bit-for-bit equivalence; ECN and transport DSACK-based
spurious-loss proof are not implemented.

One reusable timer and one heap entry per connection combine pacing, RTO,
delayed ACK, persist and teardown. The shared scheduler sleeps when empty.
Pacing emits packets at scheduled times; the virtual-time test observes actual
wire spacing. A full output queue keeps TCP data untransmitted and parks the
connection in a bounded FIFO with links embedded in the connection. Capacity
release wakes only the head when both an output slot and its packet allocation
fit. ACK progress wakes blocked writers; receive progress wakes readers,
avoiding channel/timer churn from unrelated ACKs. Readiness and
heap updates share the waiter lock to prevent a stale deadline overwriting a
writer wakeup. Neither packet timers nor a queue polling loop are required.

Custom algorithms implement congestion.Controller and register a factory:

```go
err := congestion.Register("custom", func(c congestion.Config) congestion.Controller {
    return NewCustomController(c) // a fresh, independent instance on every call
})
```

Registration rejects empty names, duplicate names and nil factories. Creation
rejects unknown algorithms, invalid MSS/window parameters and nil results. A
factory is trusted plugin code and must not panic or return shared mutable
instances. Built-in factories always allocate independent state. Configuration
changes take effect when a new stack/connection is created; active controller
state is not hot-swapped.

## Bounds, IP and UDP

Defaults: 8192 TCP flows, 1024 UDP sockets, 1024 output packets, 1MiB queued TCP
send bytes per LocalTun connection (6MiB for RemoteTunnel), 16384 send segments
and 8192 receive chunks. Receive
windows begin at 64KiB (LocalTun) or 256KiB (RemoteTunnel) and can grow to 8MiB
with consumption. A global 256MiB budget accounts retained payloads and
conservative per-flow/segment/datagram metadata charges. Channel arrays, worker
stacks, maps and temporary parsing/assembly buffers add bounded implementation
overhead; MemoryBytes is accounting, not an exact process RSS measurement.
Owned payloads and cleared send descriptors share a cache bounded by the
smaller of 10MiB and one-eighth of MemoryLimit. Cached capacity remains charged,
is evictable under pressure and expires after 2–4 idle seconds. Each size class
allows up to 4096 entries within that shared byte budget. Cache links are part
of charged descriptors, so empty classes need no preallocated pointer arrays.
A 6144-byte connection charge covers the built-in controller, small retained
send/receive queues, control descriptors and IO/handshake notification channels;
reflection-based tests guard these fixed metadata charges.

IPv4 validates IHL, total length, options and header checksums. IPv6 bounds
extension traversal to eight headers, rejects unsupported source-routing/IPsec
semantics and requires UDP checksums. IPv4 UDP checksum zero is accepted; IPv6
zero-checksum tunnel exceptions and jumbograms are not enabled. Source
fragmentation works for UDP; TCP segments against MSS instead. Reassembly is
limited to 256 groups, 4MiB of fragment payload, 128 pieces/group and 30 seconds.
Any overlap poisons the entire group until expiry for both families. Metadata
is also charged to the global budget.

UDP socket queues allow 64 datagrams and a bounded receive-byte budget. Proxy
UDP forwarding is stateless with a bounded datagram channel: destination churn
does not create a new core flow entry. Existing application NAT owns proxy flow
idle expiry. Explicit UDP sockets live until Close. ICMP supports v4/v6 echo,
unreachable/time-exceeded generation, quoted TCP/connected-UDP errors and TCP
PMTU reduction, with a 100 packets/second, burst-100 response limit. Echo is a
local stack response, like the existing gVisor TUN default; it does not measure
remote destination RTT. UDP reports associated ICMP errors to its connected
reader; a per-destination UDP PMTU cache is not implemented.

## Configuration and compatibility

The current inbound contract uses JSON, not a new protobuf schema. Opt in with:

```json
{
  "type": "tun",
  "tun": {
    "name": "tun://tun0",
    "portal": "172.19.0.1/24",
    "portalV6": "fd00::1/64",
    "mtu": 1500,
    "driver": "channel",
    "stack": "lightweight",
    "congestionControl": "cubic"
  }
}
```

`device.TunConfig` uses `congestion_control` internally; the public contract uses
`congestionControl`, matching its existing camel-case fields. Empty stack keeps
the previous driver selection exactly; empty congestion control selects CUBIC
only after lightweight is explicitly selected. Reno/BBR are selectable. Unknown
stacks/algorithms, legacy-driver combinations and invalid MTUs return errors
before opening a device. The adapter supports the channel/default device mode;
fdbased and system_gvisor remain legacy implementations, not lightweight aliases.

Linux opens IFF_TUN|IFF_NO_PI without VNET or offload. Existing native fd devices
must satisfy that contract; VNET/TAP/packet-info fds are rejected. macOS utun and
Windows use the existing offset-aware packet wrapper, and Android uses the
validated Linux fd path. The new Linux path currently has one queue; offload,
GSO/GRO and multiqueue acceleration are unavailable. No offload performance
claim is made. Existing gVisor/tun2socket openers and defaults are unchanged.
System address/route installation and PostUp/PostDown remain in the adapter;
NewTun's existing routeAccepter owns route updates and cleanup before device
closure.

### WireGuard tunnel integration

WireGuard, AmneziaWG and MASQUE construct `wireguard.LightweightNetTun` with
the `RemoteTunnel` profile and default CUBIC + HyStart++. The remote profile
starts with a 256KiB receive window and permits 6MiB of queued send data per
connection. The TUN inbound congestion selector does not configure outbounds.
Their existing keys, peers, allowed IPs, and encrypted transports retain their
contracts. The new stack requires MTU 1280..65535; zero selects the adapter's
existing default (1500, or 1400 for AmneziaWG).

The packet bridge copies directly between borrowed engine and stack buffers.
It acknowledges each copy before releasing the writer, including during Close;
it has no per-packet allocation or retained packet queue. Both engine TUN APIs
retain their required prefix/suffix space and offset handling. Unconnected UDP
sockets and wildcard TCP listeners support IPv4 and IPv6 on one ephemeral port.

The existing `wireguard.NetTun` factory remains available to the other VPN
implementations. OpenVPN, GlobalProtect, SoftEther, L2TP and VPNKit retain
their gVisor transport and concrete socket types.

Local interoperability tests use two encrypted WireGuard engines over loopback,
with gVisor as the independent peer stack. They cover IPv4/IPv6 bulk TCP,
half-close, UDP across multiple destinations and both families, cancellation,
and passive ephemeral listeners. AmneziaWG's TUN adapter has a dual-stack
offset/ownership regression test. External AmneziaWG servers and remote MASQUE
services still require separate integration qualification.

Peer TCP resets retain the standard `syscall.ECONNRESET` cause. Relay logs
classify these expected disconnects at Debug, while other failures remain Error.

## Validation and remaining acceptance work

See the benchmark report for commands, raw results and environment limitations.
Both gVisor and Linux kernel peers exercise IPv4/IPv6, three algorithms, active
and passive TCP, payload/order validation and half-close. Linux also exercises
UDP fragmentation in both directions and kernel ping. Virtual-time tests cover
wraparound, overlaps, window scaling/reopening, SACK validation, fast retransmit,
Karn sampling, TIME-WAIT, RST, pacing, blocked IO and output queue pressure.

The TUN inbound remains opt-in; the migrated outbounds use lightweight by default.
Additional conformance and
long-duration hostile-network testing is required before considering retirement
of either legacy stack. In particular, exhaustive simultaneous-open/close and
keepalive/persist fault matrices, timestamp/PAWS/ECN support, independent
broader congestion-control fairness studies beyond the shared-bottleneck
profiles recorded in the report, real mobile/macOS/Windows runtime runs,
UDP PMTU caching and Linux offload/multiqueue are not established here. Do not
interpret platform compilation or passing interoperability cases as exhaustive
RFC conformance or replacement readiness.
