# Traffic control

Consolidates the implementation from backend #583–#585/#588 and the design in RFC #582. The management UI is in yuhaiin-react. Shaping is disabled by default; admission budgets and lightweight output scheduling still protect resources.

Authenticated group/user/credential shaping, quotas and admission policies are
documented in [Identity resource governance](../resource-governance.md). They
extend this same engine and the existing user-usage report.

## Ownership and integration

`pkg/net/trafficcontrol` owns policy compilation/activation, aggregate token buckets, resource governors, stream leases, connection pacing, packet classification, FIFO/FQ-CoDel output queues and diagnostics. Protocol adapters retain transport-specific buffer/session ownership and routing. They depend on small capabilities (`Budget`, `BufferedResources`, `PolicyResolver`, `OutputQueue`, optional `QueueReporter`); they do not implement another QoS engine.

- `Controller` owns global/NAT budgets and inbound stream-scope lifetimes. Closing or removing an inbound retires its scope; outstanding leases release exactly once. A re-added ID shares its still-active scope.
- NAT acquires a session before starting workers and releases it when the final worker exits, including autonomous retirement. It charges queued bytes until DNS/dial/send work finishes or ownership transfers. The existing source/migration-keyed shared UDP socket and full-cone reply semantics are preserved.
- `WrapConn` charges the client-facing stream before ordinary relay or HTTP Gateway interception. Both paths share one charging owner. Cancellation and transport deadlines interrupt pacing; extending a read deadline preserves the unadmitted tail, and half-close forwards to the transport.
- The lightweight TUN adapter supplies owned buffers to one `OutputQueue`. Classification, host/flow scheduling, overload admission and drop accounting live in trafficcontrol. Release callbacks run outside queue locks. Other TUN stacks keep their existing synchronous device semantics.

## Configuration

Use POST RPC endpoints `/api/v2/rpc/traffic_control.get`, `.put`, `.status`. Persistence uses the existing SQLite inbound store. Startup loads and validates policy before opening listeners; a failed save/validation never replaces the active configuration.

```json
{
  "enabled": true,
  "global": {
    "upload": {"bytesPerSecond": 12500000, "burstBytes": 65536},
    "download": {"bytesPerSecond": 12500000, "burstBytes": 65536}
  },
  "defaultProfile": "balanced",
  "profiles": {
    "balanced": {"upload": {}, "download": {}},
    "bulk": {"upload": {"bytesPerSecond": 1250000}, "download": {"bytesPerSecond": 1250000}}
  },
  "inboundProfiles": {"inbound-id": "bulk"},
  "routeProfiles": {"route-rule-id": "bulk"}
}
```

API rates are **bytes/s**; the UI uses decimal Mbps (1 Mbps = 125,000 bytes/s). Zero rate/zero burst means unlimited. A positive rate with omitted/zero burst receives a 64 KiB burst. Explicitly tiny bursts can intentionally reject UDP datagrams larger than the bucket.

Global + inbound + selected route caps compose. The default profile applies only when neither inbound nor route has an explicit binding. Each bound scope gets its own aggregate bucket even if several scopes use one profile definition. Route IDs come from the existing matcher; QoS does not rerun routing.

Activation is atomic. Established TCP streams and later UDP datagrams use current bindings/rates. Global buckets retain token balances across updates, including unrelated edits; surviving scopes retain balances as rates change. Old and new connections cannot obtain separate global bursts by updating settings. Waiting stream writes wake on policy changes. A paced wait takes at most about 50 ms of credit (or one byte at very low rates); an available initial burst can be sent immediately.

TCP accounts bytes crossing the client-facing stream: intercepted HTTP includes its HTTP framing, and TLS includes bytes present at that boundary. UDP accounts datagram payload. These are admitted bytes, not physical-wire bytes: encapsulation/retransmission overhead is excluded, and an admitted downstream write may still fail. UDP over-limit admission drops immediately; TCP applies backpressure.

## Lightweight output scheduling

`TunProtocol.outputScheduler` selects `fifo` (default) or explicitly opts into `fq_codel` for the lightweight driver. Other drivers reject an explicitly set scheduler. The UI reuses the existing TUN settings selector and clears the field when switching away from lightweight.

FQ-CoDel uses outer destination-IP host groups and inner flow hashes with byte DRR and CoDel-style AQM. Host grouping prevents one host multiplying its share by opening many flows; it is not authenticated user identity. Malformed packets share a bounded fallback group. Internally generated TCP control/ICMP packets get a bounded weight (1–4); DSCP and port 53 are not trusted priority signals.

One shared packet/byte budget bounds all groups. At overload a new host can displace backlog from the heaviest competing host, so a monopolizing host cannot permanently close admission. Same-host overload preserves backpressure rather than evicting previously accepted local TCP output. A reserved slot/byte quantum prevents one flow consuming the entire queue. Sparse operation keeps one unclassified packet inline; flow state is only built when contention appears. FIFO preserves the default admission order and avoids fair classification/AQM costs through the same ownership interface. Scheduling is a per-stack choice, independent of rate-limit policy; enabling rate limits does not silently enable fairness.

Output queue readiness and `Close` share the queue ownership boundary. Closing rejects new admission and wakes blocked readers; the adapter joins its writer before draining remaining buffers. Accepted packets are never released by `Close` itself. Device batches drain only already-available packets under one lock/time sample. The single-packet device writer prefetches at most 32 packets; it never waits to fill a batch and releases the unwritten suffix on error/close. Prefetching creates a bounded service window for newly arriving flows, like an existing native device batch, while queued host/flow order still uses the same DRR/AQM core.

Packet timestamps are relative to one monotonic epoch, excluding wall-clock reads from the output path. Active host/flow hints avoid repeated hash-map lookups and are invalidated before descriptor recycling.

## Diagnostics and validation

Status exposes global/NAT resource counters, admitted bytes/pacing waits, up to 64 inbound scopes and up to 64 output queues. Queue counters distinguish AQM, overload eviction and admission rejection. IDs come from configured inbounds; no per-flow/IP/user metric labels are exported. Unsupported stacks omit queue reports. `truncated` signals bounded output.

Run `go test ./...`, `go vet ./...`, workflow-pinned golangci-lint, focused race/fuzz and cross-build jobs in `.github/workflows/traffic-control.yml`. Linux native tests require a working isolated user/network namespace and `/dev/net/tun`:

```sh
unshare -Urn go test -tags=lightweight_kernel ./pkg/net/proxy/tun/lightweight -run '^TestLinuxKernel' -count=1 -timeout=120s
BASE_REF=upstream/main scripts/traffic-control/benchmark.sh
```

The benchmark script uses real timed runs, sequential baseline/current execution and fixed filters. Set `OUTPUT_DIR`, `BENCH_COUNT`, `BENCH_TIME` or `GOMAXPROCS` as needed. The frontend `scripts/check-traffic-control.mjs` drives an isolated `/opt` Chrome against a scratch backend (`TRAFFIC_BACKEND`), tests pagination beyond 200, precise rate save/reload, discard and mobile controls. See [measurements](benchmarks.md) for measured results and limits.

## Remaining design boundaries

FQ-CoDel applies to lightweight output, not gVisor/TUN2Socket or physical WAN interfaces. Adding asynchronous queues to those adapters needs explicit batch-prefix acceptance, buffer ownership, ordering and close/drain contracts. Do not insert a second byte limiter at the device boundary without defining one accounting owner.

Authenticated peer fairness requires trusted metadata from ingress protocols; IP hashing cannot establish identity. Cross-compilation proves build compatibility only. Darwin/Android/Windows native execution, real multi-host TCP/QUIC/DNS latency under saturation and WAN bottleneck shaping still require suitable devices/workloads. Linux tests and localhost benchmarks do not establish those acceptance items.
