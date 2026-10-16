# Lightweight TCP/IP stack

Status: experimental opt-in implementation. Replacement readiness and the full
acceptance matrix are not established; measured results and gaps are explicit below.

The later [transport optimization checkpoint](benchmarks/lightweight-optimization.md) records updated
measurements, idle baselines, correctness fixes and pending BBR v3/HyStart++ work.
The original full matrix below is historical and predates those changes.

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
3. Independent Reno, CUBIC and BBR v1 controllers with actual scheduled pacing.
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
This implementation is written independently; no reference implementation
source is vendored or copied. Protocol sources include RFC 9293, RFC 5681,
RFC 6582, RFC 6298, RFC 7323, RFC 2018, RFC 8200, RFC 5722, RFC 9438 and the
BBR v1 congestion-control draft. Validation evidence and outstanding gaps are
recorded below as the implementation is exercised.

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
Validated SACK blocks mark retained segments, and RTO clears the scoreboard to
allow receiver reneging. Three duplicate ACKs trigger fast retransmit; partial
recovery ACKs retransmit the next gap. RTT estimation uses SRTT/RTTVAR, Karn's
rule and RFC 6298's one-second minimum RTO with exponential backoff. Delayed ACKs
wait at most 20ms; reordering, FIN and window updates trigger immediate ACKs.
Zero-window probes do not consume new sequence space. Optional keepalive is
scheduled only when enabled and idle. ICMP PMTU feedback validates the quoted
TCP tuple and sent sequence before reducing MSS and splitting retained data.

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
The delivery sampler records prior delivered bytes and send/ACK intervals;
compressed ACKs cannot use an interval shorter than the send interval.

Reno supplies slow start, additive growth, fast recovery and timeout reduction.
CUBIC uses a time epoch, cubic origin/K, beta 0.7, fast convergence and a
Reno-friendly estimate. HyStart++ is not implemented. BBR v1 has a ten-round
bandwidth maximum, minimum RTT aging, STARTUP/DRAIN/PROBE_BW/PROBE_RTT,
app-limited sampling, gain cycling and a scheduled pacing rate. It is an
independent implementation of the principal v1 mechanisms, not BBRv2/v3 or a
claim of bit-for-bit equivalence to Linux BBR.

One reusable timer and one heap entry per connection combine pacing, RTO,
delayed ACK, persist and teardown. The shared scheduler sleeps when empty.
Pacing emits packets at scheduled times; the virtual-time test observes actual
wire spacing. A full output queue keeps TCP data untransmitted and parks the
connection in a bounded FIFO. Capacity release wakes a waiter. Readiness and
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
closure. WireGuard/OpenVPN/MASQUE/L2TP are not migrated.

## Validation and remaining acceptance work

See the benchmark report for commands, raw results and environment limitations.
Both gVisor and Linux kernel peers exercise IPv4/IPv6, three algorithms, active
and passive TCP, payload/order validation and half-close. Linux also exercises
UDP fragmentation in both directions and kernel ping. Virtual-time tests cover
wraparound, overlaps, window scaling/reopening, SACK validation, fast retransmit,
Karn sampling, TIME-WAIT, RST, pacing, blocked IO and output queue pressure.

This remains an experimental opt-in implementation. Additional conformance and
long-duration hostile-network testing is required before considering retirement
of either legacy stack. In particular, exhaustive simultaneous-open/close and
keepalive/persist fault matrices, timestamp/PAWS/ECN support, independent
congestion-control fairness studies, real mobile/macOS/Windows runtime runs,
UDP PMTU caching and Linux offload/multiqueue are not established here. Do not
interpret platform compilation or passing interoperability cases as exhaustive
RFC conformance or replacement readiness.
