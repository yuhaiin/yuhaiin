# Measurement routing and traffic policy

Network probes and active download tests retain their explicitly selected Node
and actual protocol chain. Application runtimes now gate these operations on
successful initial routing and traffic-policy activation. The existing forwarding
path, Selector policies and manual selection defaults are unchanged.

## Admission and routing

`Route.PrepareProbe` uses the existing matchers, destination recovery, DNS settings
and rule identity. Gateway actions are skipped while ordinary block decisions
still reject the probe. It does not call the route dialer, choose another Node
or recursively enter an automatic Selector. Each new measurement connection uses
the candidate proxy already owned by NodeRuntime.

Streams share the inbound engine's root/session governors. UDP channels share
its existing datagram budget. Measurements have no authenticated local user or
inbound identity, so the existing global/default profiles and matched rule profile
apply. An administrator can bind a route profile matching the measurement target.
Changing caps affects later operations on existing measurement connections through
the same live Traffic Control policy objects used by ordinary forwarding.

TCP reads are charged as download and writes as upload. The implementation reuses
the existing stream pacing, deadline and cancellation code with the direction
reversed at the outbound boundary. UDP uses the existing per-datagram admission
mechanism; a local denial returns a policy error instead of sending traffic or
inventing a remote node failure. It never splits a UDP session for balancing.

Optional STUN tests can contact alternate endpoints. Up to eight destinations are
prepared and checked per probe, with a single pinned PacketConn. Each distinct
endpoint receives its route/rate identity; subsequent packets reuse that identity
and observe live cap updates. This bounded cache exists only inside a probe,
not in the ordinary NAT forwarding path. Unsolicited replies preserve the existing
UDP session semantics.

## Startup and failure semantics

`policyState` in the existing monitoring status API reports:

- `waiting`: the application has not successfully hydrated routing or traffic
  policy. Probes/tests pause before outbound construction and speed-budget spend.
- `enforced`: application routing/admission/traffic controls are attached.
- `standalone`: a core/embedder has not attached application policy. Its existing
  direct Node API behavior remains available; the UI makes that scope explicit.

The full app requires policy attachment. A failed initial route activation is not
reported as ready. A later failed edit that retains a previously active routing
snapshot continues using that last good snapshot. Fixing stored QoS and applying
it through the existing API resumes readiness without restarting the runtime.
The UI polls this status while its monitoring dialog is open; backend decisions
and schedules do not depend on that dialog.

Local rate/session denial, pacing deadline, caller cancellation and route block
are distinct from remote transport failure. HTTP can replace a pacing error with
its request deadline. If actual pacing occurred during that timed-out probe, its
full-request result is ambiguous and skipped rather than used to condemn a node.
TLS certificate verification errors remain transport failures. Complete active
health probes contribute one outcome each; TCP establishment/first-response
substeps update traffic counters without double-counting recovery. Passive
connections and speed tests retain their existing transport observations.
The shared scheduler counts policy-limited operations as skipped.

## Connection lifetime and bounded cancellation

A temporary HTTP dial context ends after connection establishment. The policy
wrapper therefore retains the complete probe lifetime for pacing and leases.
HTTP latency and throughput transports additionally own a bounded set of at most
16 connections and close them synchronously on completion, including redirects
and late dial completions. Legacy GET redirects retain their existing limit;
active HEAD/download tests still refuse redirects.

The download payload timer cancels an I/O context with a distinct cause. It does
not rely on `response.Body.Close`, which can wait behind a paced body read.
Cancellation closes the underlying Node connection and interrupts local pacing.
Intentional payload-duration truncation remains normal completion when enough
bytes were sampled. A caller cancellation or whole-test timeout remains an error.
TLS verification remains enabled for scheduled HTTPS and active downloads.

Direct UDP has an optional context-aware write capability so endpoint DNS lookup
uses the probe context instead of an unrelated background timeout. Ordinary
PacketConn writes retain their established lifetime/behavior. Closing, timing out
or deleting a probe releases stream/datagram leases even when the caller forgets
to close its returned measurement connection.

## Qualification and remaining boundary

Tests use virtual time, local TCP/TLS servers and mock resolvers. Coverage includes
upload/download orientation, local-vs-remote error classification, shared/live
route caps, alternate STUN destination denial/cache bounds, session cancellation,
UDP DNS cancellation, HTTP dial-vs-request lifetime, paced TLS payload truncation
and HTTP deadline classification. A subprocess starts the actual app with invalid
stored QoS, repairs it, verifies a real route block and then probes a real local
TCP endpoint while that route points at an unready automatic Selector. This
checks startup gating, recovery and non-recursive fixed-node egress together.
Unprivileged hosts may report an unrelated CAP_NET_ADMIN requirement when the
existing nftables module closes; only that cleanup error is tolerated by the
subprocess test, and all probe checks still execute.

Shared manual/periodic admission and transport-inclusive reservations are now
implemented in the [measurement bounds follow-up](measurement-bounds.md). The
allowance covers the logical Node stream boundary; VPN framing/control traffic
and construction remain outside it. This does not complete Phase 1 qualification.

## Forwarding cost

Linux/amd64 Ryzen 5 5600G comparison against the circuit parent `bcdc4634`,
three samples of 500 ms per case, using the same deterministic transport:

| Operation | Parent ns/op | Current ns/op | Current bytes / allocs |
| --- | ---: | ---: | ---: |
| SelectorNewFlow/manual/tcp | 694.20 | 686.10 | 272 / 5 |
| SelectorNewFlow/manual/udp | 446.60 | 441.70 | 288 / 6 |
| SelectorNewFlow/failover/tcp | 865.70 | 861.00 | 328 / 8 |
| SelectorNewFlow/failover/udp | 556.70 | 544.10 | 344 / 9 |
| SelectorNewFlow/weighted/tcp | 906.60 | 902.40 | 328 / 8 |
| SelectorNewFlow/weighted/udp | 590.40 | 573.40 | 344 / 9 |
| ObservedPacketSend | 9.10 | 4.28 | 0 / 0 |

[Parent output](benchmarks/data/selector-2026-10-26/policy-baseline.txt) and
[current output](benchmarks/data/selector-2026-10-26/policy-current.txt) include
repetitions and allocation counts. Ordinary UDP sends remain allocation-free.
The policy adapters are installed only for measurement traffic. These are CPU
overhead measurements, not physical link throughput.

```sh
go test ./pkg/node -run '^$' -bench 'BenchmarkObservedPacketSend|BenchmarkSelectorNewFlow' -benchmem -benchtime=500ms -count=3
```

## Periodic work reuses established VPN sessions

A cached proxy object is not proof that its lazy VPN login has completed.
Periodic probes and scheduled speed tests now carry a context marker through
Set, endpoint and other node chains. The node factory refuses new expensive VPN
constructors under that marker, including after credential invalidation removes
a cached client. Tailscale cannot initialize an identity or control client, and
GlobalProtect cannot wake its idle demand-based reconnect path. OpenVPN, L2TP
and SoftEther return a local skip when their reconnect supervisor has no current
session. The existing supervisors keep their own configured lifecycle; probes do
not start additional login loops. Manual tests and ordinary traffic retain their
existing protocol behavior.

Native status preflight avoids testing a known idle/unavailable VPN. The context
marker also protects the race where a previously ready session becomes unavailable
after preflight. A local reuse refusal is a skipped measurement, not a remote
failure. If a periodic speed test already reserved its allowance before that
race, the existing conservative reservation still applies.

Session snapshots are read from existing protocol state. No per-node polling
worker or timer is added. Cached lookups for one node are direct; entry locks use
TryRLock so status/selection inspection does not wait behind proxy shutdown.
Tailscale status uses TryLock to avoid waiting behind expensive initialization.
Only snapshot compilation inspects native availability; forwarding continues to
read the compiled immutable choice. Known failed/closed/reconnecting sessions
and unavailable authentication/control are ineligible automatically without
inventing passive network failures. Idle demand-based sessions remain eligible
for normal application traffic to wake when supported. Explicit manual selection
keeps its existing behavior.

Native lifecycle follow-up microbenchmarks on Linux/amd64 Ryzen 5 5600G,
median of three 300 ms samples compared with consolidated parent `56892747`:

| Operation | Parent ns/op | Current ns/op | Current bytes / allocs |
| --- | ---: | ---: | ---: |
| SelectorNewFlow/manual/tcp | 702.60 | 707.10 | 272 / 5 |
| SelectorNewFlow/manual/udp | 457.90 | 449.00 | 288 / 6 |
| SelectorNewFlow/failover/tcp | 871.60 | 867.00 | 328 / 8 |
| SelectorNewFlow/failover/udp | 566.40 | 542.00 | 344 / 9 |
| SelectorNewFlow/weighted/tcp | 913.30 | 902.00 | 328 / 8 |
| SelectorNewFlow/weighted/udp | 600.60 | 571.80 | 344 / 9 |
| NativeSelectionAvailability/100 | n/a | 2476.00 | 952 / 5 |
| NativeSelectionAvailability/1000 | n/a | 32837.00 | 9368 / 11 |
| ObservedPacketSend | 4.29 | 4.02 | 0 / 0 |

[Parent output](benchmarks/data/selector-2026-10-26/native-parent.txt) and
[current output](benchmarks/data/selector-2026-10-26/native-current.txt) retain all
repetitions. Native availability measures one scan of 100/1,000 cached session
providers, with 10% unavailable; that work runs during snapshot compilation,
not per connection or packet. The flow/send cases use deterministic transports
and retain allocation counts. These timings are CPU overhead, not physical-link
throughput or the final heap/goroutine deployment qualification.
