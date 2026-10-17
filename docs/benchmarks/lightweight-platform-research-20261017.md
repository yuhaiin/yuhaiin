# Lightweight stack: platform APIs and protocol research

Verified on 2026-10-17. This document distinguishes documented API behavior from
engineering proposals. The [baseline audit](lightweight-performance-review-20261017.md)
and [optimization report](lightweight-offload-optimization-20261017.md) contain
measurements. No third-party benchmark is treated as a theoretical userspace limit.

## Platform boundaries

### Linux

`readv(tunfd, iov...)` scatters **one frame**; `writev` gathers **one frame**.
`drivers/net/tun.c` calls one `tun_do_read` or `tun_get_user` per operation.
An iovec containing several complete IP packets is not a packet batch.
Socket `sendmmsg/recvmmsg` cannot be applied directly to a TUN character device.
A useful gather layout is `[virtio header, IP/TCP header, payload fragments]`.
[Linux TUN implementation](https://github.com/torvalds/linux/blob/master/drivers/net/tun.c).

`IFF_VNET_HDR` and `TUNSETOFFLOAD` negotiate `TUN_F_CSUM`, `TUN_F_TSO4` and
`TUN_F_TSO6`. They carry partial-checksum and TCP segmentation metadata.
`TUN_F_USO4/USO6` refer to UDP segmentation, distinct from deprecated UFO.
Input buffers must accommodate super-packets. Capability negotiation must use
the actual descriptor and preserve a plain-packet fallback.
[Linux TUN UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h).

GSO preserves the eventual wire MSS; increasing interface MTU is a different
experiment. Preserving a super-packet through parsing and receive queues avoids
more per-packet work than immediately splitting it. TSO requires partial checksums.
[Segmentation offloads](https://www.kernel.org/doc/html/latest/networking/segmentation-offloads.html).

Multiqueue requires separate `TUNSETIFF(... IFF_MULTI_QUEUE)` calls. `dup(fd)`
shares an existing queue. Multiple queues need flow-affine state execution and
primarily help multiple flows; they do not automatically accelerate one flow.
[Linux TUN/TAP documentation](https://docs.kernel.org/networking/tuntap.html).

Recent documentation also describes `IFF_BACKPRESSURE` for qdisc/AQM behavior
when the TUN ring fills. The installed host UAPI does not expose this flag; it
was not enabled or tested. Latency and throughput need separate qualification.
[TUN qdisc backpressure](https://docs.kernel.org/networking/tuntap.html#qdisc-backpressure).

### macOS

Ordinary utun uses a system-control datagram socket with a four-byte address-family
prefix. XNU preserves frame boundaries through `utun_ctl_send` and
`ctl_enqueuembuf(... CTL_DATA_EOR)`. A single-record `writev` can gather prefix,
headers and payload; concatenating complete packets does not make a batch.
This is a source/API conclusion, not a macOS performance measurement.
[XNU utun implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_utun.c).

Skywalk/channel/flowswitch options in XNU are not evidence of a stable,
unentitled replacement for Linux virtio-net. SDK availability, entitlements,
initialization constraints and supported OS versions require separate work.
[XNU utun definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_utun.h).

NetworkExtension's `NEPacketTunnelFlow` exposes packet-array read/write APIs.
If this integration is used, preserve the native batch through the bridge;
array APIs alone do not establish zero-copy delivery.
[Apple NEPacketTunnelFlow](https://developer.apple.com/documentation/networkextension/nepackettunnelflow).

`sendmsg_x/recvmsg_x` are declared in Apple's **private** socket header and
require protocol-handler support. Any experiment needs a real utun self-test,
accepted-prefix handling, EAGAIN/close tests and version fallback. They should
not become the default based on Linux measurements.
[Apple private socket declarations](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/socket_private.h),
[XNU syscall implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_syscalls.c).

Priorities: remove adapter copies, reserve utun prefix space in owned packets,
reduce software checksum cost, then profile stream gathering and wakeups on a Mac.
No macOS host was available for runtime validation in this investigation.

### Android

`VpnService.Builder.establish()` documents one packet per read/write; the fd
is nonblocking by default. Native code can own a detached fd. `setBlocking`
changes blocking mode, not packet framing.
[Android VpnService.Builder](https://developer.android.com/reference/android/net/VpnService.Builder#establish()).

AOSP Android 16 `create_interface` uses `IFF_TUN | IFF_NO_PI`, without VNET or
multiqueue. Ordinary app policy allows receiving an already-open TUN fd from
the framework and querying `TUNGETIFF`; it does not grant general device access
or unrestricted offload negotiation. A newer Linux kernel is insufficient.
[Android 16 Vpn.cpp](https://android.googlesource.com/platform/frameworks/base/+/android16-release/services/core/jni/com_android_server_connectivity_Vpn.cpp),
[AOSP app SELinux policy](https://android.googlesource.com/platform/system/sepolicy/+/main/private/app.te).

The audit confirmed these restrictions using an actual VpnService descriptor in
ordinary app domains on Android 14/4 KiB and Android 15/16 KiB x86_64 emulators:
`TUNGETIFF=0x1001`, no VNET, and `TUNSETOFFLOAD(0)` denied. Prioritize native I/O,
copy/checksum/queue improvements and bounded buffers. Root/OEM paths require
separate labels and tests. Emulator throughput is not physical arm64 evidence.

## Standards and drafts

| Source and status at verification | Relevance and priority |
|---|---|
| [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html), Internet Standard | Required sequence, window, state, FIN/RST and overlap correctness. |
| [RFC 2018 section 4](https://www.rfc-editor.org/rfc/rfc2018.html#section-4) | The first SACK block must cover the triggering segment when cumulative ACK does not advance. The audit found and this change fixes a violation. |
| [RFC 7323](https://www.rfc-editor.org/rfc/rfc7323.html), Proposed Standard | Window scaling exists. Timestamp negotiation, RTTM and PAWS remain important for high-rate remote paths. Sequence-wrap arithmetic alone is not PAWS. |
| [RFC 5681](https://www.rfc-editor.org/rfc/rfc5681.html) | Delayed ACK must preserve timely feedback, including gaps and window reopening. Large GSO input must not be treated as one small wire segment. |
| [RFC 6675](https://www.rfc-editor.org/rfc/rfc6675.html) | SACK recovery requires a sender scoreboard, beyond merely parsing options. Existing recovery still needs broader conformance qualification. |
| [RFC 8985](https://www.rfc-editor.org/rfc/rfc8985.html), Proposed Standard | RACK/TLP can improve tail-loss and small-flight recovery; requires reliable transmission timing and reordering state. |
| [RFC 6937](https://www.rfc-editor.org/rfc/rfc6937.html) | PRR is a follow-up recovery-send-control direction. |
| [RFC 9438](https://www.rfc-editor.org/rfc/rfc9438.html), Proposed Standard | CUBIC requires correct flight, pacing, window and recovery accounting; it cannot remove syscall cost. |
| [RFC 9768 AccECN](https://datatracker.ietf.org/doc/html/rfc9768), April 2026 Proposed Standard | Published RFC, no longer the old accurate-ecn draft. Needs negotiation, counters, controller feedback and an ECN/AQM path. Lower priority for localhost CPU limits. |
| [TARR revision 12](https://datatracker.ietf.org/doc/draft-ietf-tcpm-ack-rate-request/12/), July 2026 draft, intended Experimental | Negotiated ACK-rate requests need peer support; not a generally deployed tuning switch. |
| [BBR revision 06](https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/06/), July 2026 draft, intended Experimental | The repository already has BBR v3. Improve delivery sampling/pacing/recovery and measure fairness rather than adding another algorithm name. |
| [RFC 4821](https://www.rfc-editor.org/rfc/rfc4821.html) and [RFC 8899](https://www.rfc-editor.org/rfc/rfc8899.html) | TCP PLPMTUD and datagram DPLPMTUD respectively; useful follow-ups for ICMP-filtered paths. |

Applicability: a local split-TCP TUN normally terminates the local TCP leg while
an OS socket owns WAN congestion control. RemoteTunnel traffic can have genuine
RTT/loss on the userspace TCP leg. Do not extrapolate localhost BBR performance
to remote congestion-control behavior.

## What hev actually does

Pinned source: `873541b81f00f8fd462392fc622adbb8a8cd59b0`, including locked
[lwIP and task-system submodules](https://github.com/heiher/hev-socks5-tunnel/blob/873541b81f00f8fd462392fc622adbb8a8cd59b0/.gitmodules).
Upstream lwIP defaults are not a substitute for its customized configuration.

- Upload retains pbuf chains, writes the upstream stream with `writev`, and
  credits `tcp_recved` only for accepted bytes. Download uses `readv` into a ring,
  references that storage in `tcp_write`, and releases it after ACK callbacks.
  `tcp_splice_*` is not Linux `splice(2)`.
  [TCP session](https://github.com/heiher/hev-socks5-tunnel/blob/873541b81f00f8fd462392fc622adbb8a8cd59b0/src/hev-socks5-session-tcp.c).
- Linux negotiates VNET/checksum/TCP and UDP segmentation, gathers a virtio
  header and pbuf chain in one `writev`, and supports an optional local-delivery
  jumbo shortcut. The latter is not normal peer-MSS-preserving GSO and must not
  be used for arbitrary forwarding.
  [Linux backend](https://github.com/heiher/hev-socks5-tunnel/blob/873541b81f00f8fd462392fc622adbb8a8cd59b0/src/hev-tunnel-linux.c).
- Its macOS backend reports no offload capabilities. Linux TSO results therefore
  do not describe macOS acceleration.
  [macOS backend](https://github.com/heiher/hev-socks5-tunnel/blob/873541b81f00f8fd462392fc622adbb8a8cd59b0/src/hev-tunnel-macos.c).
- Its pinned lwIP configuration disables IP/TCP/UDP input checksum checks.
  Comparing actual implementations is useful, but does not compare equal
  validation work. Keep our raw-wire checksum validation enabled.

The [official benchmark wiki](https://github.com/heiher/hev-socks5-tunnel/wiki/Benchmarks)
uses an older release and a specific jumbo/multiqueue/multiprocess topology.
Neither those figures nor one current single-instance result are an absolute
userspace-stack ceiling.

## Further experiments

Stream `WriterTo`/vectored drain could avoid receive-chunk merging copies, but
must keep leases valid outside the connection lock, consume only accepted bytes,
and preserve backpressure. A download ring must retain retransmission data until
cumulative ACK; SACK cannot release storage early. Profile before introducing
these lifetime contracts.

A larger configured **local** TUN MTU negotiates a larger MSS on that local leg;
the separate upstream OS socket still handles the real link MTU. This is distinct
from both GSO and hev's local jumbo shortcut. Android/macOS experimentation must
also cover UDP fragments, ICMP and forwarding before changing defaults.

Execution sharding and multiqueue should follow flow-count/CPU profiles. Keep
per-batch work bounded and measure small-flow latency and fairness alongside
throughput. Linux namespaces/Podman cannot substitute for XNU, Android policy,
physical-device thermal behavior or real WAN qualification.
