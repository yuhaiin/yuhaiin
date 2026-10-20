# Traffic Control P4 follow-up

This follow-up is stacked on backend P3 [#585](https://github.com/yuhaiin/yuhaiin/pull/585), which builds on P1/P2 [#584](https://github.com/yuhaiin/yuhaiin/pull/584) and P0/P1 [#583](https://github.com/yuhaiin/yuhaiin/pull/583), plus frontend P3 [#504](https://github.com/yuhaiin/yuhaiin-react/pull/504), under RFC [#582](https://github.com/yuhaiin/yuhaiin/pull/582). It hardens ownership and activation boundaries found while auditing P0–P3 and completes the existing page's binding selection behavior. It does not claim universal fair scheduling or production qualification across every tunnel backend.

## Backend corrections

- UDP NAT resolves the selected route's Traffic Control policy from the route ID already attached to the routed connection. It does not invoke a second route matcher. The source-keyed shared UDP session and full-cone reply behavior remain unchanged.
- UDP byte reservations remain charged while a dequeued packet is waiting on DNS resolution or a dial. A reservation is released on completion or transferred to the pending-resolution owner; it is not dropped at dequeue and reacquired later.
- Inbound stream-scope governors are retired when an inbound is removed or disabled. Active leases keep their original scope and quota until release, while a re-added inbound cannot accidentally create a second governor beside an active old lease.
- TCP shaping refunds the unused part of a token reservation after a partial write, while clamping debt to the configured burst floor.
- Hysteria2 rejects an explicitly empty TLS identity before opening listeners or configuring port redirection.

## Frontend corrections

- Inbound and route binding choices use the APIs' server pagination. All entries remain reachable, including entries beyond the former first-page/table caps; configured IDs outside the current page remain visible so existing policy can still be edited.
- Configuration save success is independent of the diagnostics refresh. A successful write remains reported as saved when the separate status request fails.
- English, Japanese and Korean resources expose the binding-list failure state consistently.

## Qualification and measurements

The backend validation workflow runs the full Go test suite and vet, focused race coverage, a bounded packet-classifier fuzz run, targeted benchmarks, and Darwin/Windows/Android cross-compilation. The frontend workflow runs TypeScript, component tests, translation/style audits, lint and a production build. These workflows do not require privileged TUN access.

The scheduler benchmark `BenchmarkGroupedFairQueueMixedPacketSizes` compares a 1400-byte/64-byte mixed-size two-group DRR enqueue/dequeue loop against a FIFO ring using the same packets and byte-sum work. On Linux/amd64 with a Ryzen 5 5600G, five one-second runs measured DRR at 82.59–83.24 ns/op and the FIFO ring at 2.537–2.686 ns/op, with zero allocations in both. This isolates scheduler data-structure overhead; it is not network throughput, fairness under a real bottleneck, or evidence of the RFC's 5% end-to-end overhead target.

The Linux `lightweight_kernel` suite was run in an isolated user/network namespace against `/dev/net/tun`; its real-kernel TCP, UDP, ICMP and PMTU tests passed. This exercises the lightweight stack's native Linux TUN path, but not mixed-host QoS contention, gVisor/TUN2Socket, other operating systems or a physical-WAN bottleneck. No end-to-end throughput or latency result is claimed here.

## Remaining engineering blockers

- **gVisor output:** the package `Endpoint.WritePackets` synchronously copies a `PacketBufferList` to `netlink.Tun.Write` and returns the accepted prefix. Replacing this with asynchronous fair scheduling requires an explicit queue-acceptance contract, retained packet ownership, cancellation/close draining, and preservation of partial-batch semantics. Linux's native `fdbased` endpoint also uses multiple kernel queues and bypasses this wrapper. The current call path adds no asynchronous queue and preserves synchronous device backpressure per call; it does not establish a global queue-memory budget or provide host-group DRR/AQM.
- **TUN2Socket:** independent TUN readers batch TCP writes directly to the device, while UDP is handed to the NAT session path. There is no shared output queue carrying both a stable flow key and a common accepted/drop contract. Adding a generic queue at the current device interface could reorder TCP, duplicate accounting, or break multi-queue behavior. The current path has bounded per-read batches and P0/P2 NAT resource limits, but lacks the P3 host/flow scheduler.
- **Trusted identity:** WireGuard has an authenticated peer key at its tunnel receive boundary, but the current packet interfaces pass plain IP buffers to the lightweight scheduler. No authenticated peer/user metadata accompanies those buffers. Grouping by source or destination IP remains a documented fallback; deriving a peer identity from an IP address would trust spoofable packet content. A future implementation needs an authenticated metadata handoff at ingress and a lifecycle-bound scheduler key.
- **Platform and end-to-end qualification:** this host can cross-compile Darwin, Windows and Android code, but cannot establish real-device behavior for all of those platforms. Hosted Linux CI also cannot guarantee a privileged native TUN. Real multi-host traffic, QUIC/DNS saturation latency, high-PPS CPU pressure, GSO ownership, and physical-interface shaping still need a capable integration runner and workload harness.
- **Measurement model:** the current shaper accounts payload bytes at relay/UDP boundaries. It does not account for IP/tunnel encapsulation, retransmission, or physical-wire bytes. Applying an additional limiter at a native TUN/device boundary without a single charging owner risks double-shaping; physical-WAN shaping needs an explicit accounting and ownership design.

These are architectural and environment limits, not passing acceptance items. The concrete next step for gVisor/TUN2Socket is to define a per-link bounded write-queue contract that preserves batch-prefix acceptance, buffer ownership, ordering and close semantics, then integrate one backend at a time with device-backed tests. Identity work should propagate already-authenticated peer metadata through that same link boundary rather than introduce a separate identity database.
