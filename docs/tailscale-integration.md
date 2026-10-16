# Tailscale integration maintenance and validation

This adapter uses one `tsnet.Server` per outbound lifetime. A node's supplied
upstream proxy carries control, DERP, UDP discovery and encrypted peer traffic.
The default direct transport uses yuhaiin's interface selection and loop
protection. Bootstrap DNS resolves infrastructure names without changing
Tailscale's process-wide DNS cache. No global network wrapping or Tailscale
environment variables are installed by this package.

## Routing and UDP semantics

Tailscale's `Server.Dial`/`UserDial` can use host sockets for destinations without
a Tailnet route. A separate route check followed by `Server.Dial` also permits a
route-change race. This adapter instead uses upstream `UserDialPlan` for
MagicDNS canonicalization, ExtraRecords, address-family selection and route
classification, then pins TCP to `NetstackDialTCP`. Losing the route cannot turn
a refused/failed connection into system direct access.

UDP uses upstream `Server.ListenPacket`, which now works with the current
netstack. It is a real unconnected socket and can send to multiple destinations.
Every write resolves and validates its target through the instance dialer before
sending it through netstack. The initial target chooses IPv4 or IPv6; a target
of the opposite family is rejected explicitly. This is better defined than the
previous connected UDP wrapper silently delivering every `WriteTo` to the first
peer. IP writes avoid a resolver timer and watcher goroutine; hostname writes
have a deadline-aware resolution context. The adapter also preserves explicit tcp4/tcp6 and udp4/udp6 requests at the
netapi boundary, where ordinary addresses normalize those network names.
Native direct underlay sockets remain
`*net.UDPConn`, preserving Tailscale's socket-buffer and batching/offload paths.

No remote throughput claim is made. Per-write route validation costs a lookup;
its throughput effect, and custom proxy NAT/port mappings, need deployment
measurements. Proxies must provide genuinely unconnected UDP, an allocated local
UDP endpoint, deadlines and close/rebind semantics. An upstream which cannot
satisfy that contract is not made compatible by implementing an interface.

## DNS, Ping and ownership

Only port 53 on Tailscale's two service IPs is intercepted. UDP DNS wire messages
are delegated to `DNSManager.Query`; TCP retains `HandleTCPConn`. The native
manager handles transaction IDs, A/AAAA/PTR, negative responses, split routes
and configured default resolvers. Query errors are returned, never converted
into synthetic successful empty answers. Concurrent writes have independent
query contexts and a bounded reply queue. Deadline expiry and Close cancel work
and unblock readers/writers; buffers are ordinary owned slices.

Ping waits for its asynchronous ICMP callback using a buffered channel. Errors
and context cancellation propagate; latency is converted from seconds to
nanoseconds, matching `netapi.Proxy.Ping` and the direct outbound. Late callbacks
cannot block. Production ACL and ICMP availability still govern success.

`Close` is terminal and cancels shared Up work and virtual DNS connections.
The bootstrap AuthKey is set only for the synchronous `Server.Start` call and
cleared afterwards, including on failure. Cached network server objects therefore
do not retain it. A local control-server regression checks this after startup.
There is no LRU of shared outbound objects or mutable live logging callback.
Separate creations cannot silently reuse another upstream or share Close.
Context ancestry rejects immediate recursive proxy chains. A small graph of
live instance dependencies also rejects cycles across tsnet background work;
dependencies are removed at Close. If changing a dynamic upstream would change
these dependencies, recreate/close the outbound as for a configuration change.
This graph governs dependency validation, not process-global packet routing.

State directories derive an opaque ID with PBKDF2-HMAC-SHA256 (600,000 rounds),
using the auth key and a length-delimited hostname/control-URL namespace salt.
The derivation runs once during initialization, outside the packet path. Secrets and user-controlled path components do not
appear in directory names. A running state directory has one owner. A second
copy with the same identity is refused until the first node closes; distinct
configurations get distinct directories. The first start atomically moves a
legacy hostname directory into its hashed location (or moves `tailscaled.state`
for the old empty-hostname layout). Existing hashed state is never overwritten.
The `v2-` directory prefix distinguishes this from the fast SHA-256 layout of
intermediate, unreleased PR revisions. That intermediate layout is not migrated
automatically; the released hostname-based state layout still migrates as above.
Public node configuration, protobuf and frontend contracts are unchanged.

For explicitly supplied underlays, host port mapping, raw disco, captive-portal
checks and underlay ICMP latency probes are disabled per instance in the fork;
they cannot describe a remote proxy's host network. Tailnet ICMP, UDP disco,
STUN, DERP and peer-relay datagrams retain their normal transports. Native tsnet
servers without an underlay retain upstream behavior and environment proxies.

## Fork changes that remain

| Historical patch | Result |
| --- | --- |
| `2d639291` global netns wrappers | Replaced by explicit `tsnet.Server.Underlay` plumbing. Original `netns.Listener` and its `Control` field are restored. |
| `81a7de24` exported DNS map | Removed. |
| `4b5e5f66` noop DNS workaround | Removed: upstream already handles `ErrGetBaseConfigNotSupported`. |
| `f377f7ca` exported MagicDNS callback | Removed: `UserDialPlan` already canonicalizes names. |

The remaining private behavior is instance TCP/UDP/DNS transport injection,
plumbed through control HTTP/Noise, DERP, magicsock, netcheck, external DNS and
log upload. There is also a small fix closing an in-flight system dial which
completes after shutdown; it is independently suitable for upstreaming. DNS
manager logic, DNS map structure, MagicDNS normalization and the netns default
implementation require no private patch. The fork's `tsnet/UNDERLAY.md` documents
its full transport contract and tests.

## Validation record

The implementation was tested with Go 1.27.2 on Linux. The dependency is pinned
to published fork commit `223166903dc3e50a35f968ad48dd41a480ba7381`
(`v0.0.0-20261016035925-223166903dc3`); `go mod download tailscale.com`
and `go list -m -json tailscale.com` confirmed a downloaded module with checksums.
No local filesystem replacement is part of the PR.

CodeQL uses an explicitly traced archive build of `./...` and
`tailscale.com/tsnet`. Archive mode accommodates helper main packages without
an entry point. Selecting tsnet as an extraction root
includes the embedded transport implementation instead of inferring dataflow
from its external interfaces alone. The former inferred flows propagated
`Server.AuthKey` through unrelated packet reads into VPN parser logging.
No security query, logging sink or alert is suppressed by this configuration.

- `go test ./pkg/net/proxy/tailscale/...` and its `-race -count=1` variant cover
  native DNS A/AAAA/PTR/NXDOMAIN/NODATA, IPv6-only records, case and trailing-dot
  queries, a real local split/default UDP resolver, concurrent transaction IDs,
  malformed-query FORMERR, error propagation, deadlines, cancellation, blocked
  readers/writers, Close and goroutine cleanup; Ping success/error/timeout/
  cancellation; upstream selection; UDP IPv4/IPv6 and repeated socket binding;
  loop detection; distinct instance ownership and legacy state migration.
- `TestLocalTailnet` uses real local control and DERP services with two adapter
  instances, separate real socket upstreams and WireGuard/netstack. It covers
  TCP, IPv4/IPv6 UDP to multiple ports, native service DNS over UDP/TCP, rejection
  of non-Tailnet TCP/UDP, rebind, state ownership, configuration replacement and
  close isolation. No Tailnet account or external service is required.
- The fork's focused tests and race suite cover netns, tsdial, DNS/resolver,
  netcheck, UDP relay, tsnet, magicsock, DERP HTTP and control HTTP/Noise. Local
  fork integration tests also use real STUN. Only the pre-existing magicsock
  `TestNetworkSendErrors/network-down` assertion fails because this host rejects
  `sendmmsg` with `operation not permitted`; reproduced on upstream `9128778b6`.
- `GOMAXPROCS=4 go test -p=4 -timeout=5m ./...` was executed in both repositories.
  The fork additionally has existing `cmd/containerboot` port-9002 conflicts and
  `tstest/integration/TestC2NDebugNetmap` panic (`body closed by handler`), each
  reproduced on upstream `9128778b6`. yuhaiin has an unrelated
  `pkg/utils/syncmap/TestLoadOrCreate` timeout with `GOMAXPROCS=4`, reproduced on
  unmodified `main` (`08131975`) using a 15-second diagnostic timeout. That test
  calls `t.Parallel` inside the goroutine which its subtest waits for. Tests and
  assertions were not removed or skipped to hide these failures.
- `go test -timeout=2m ./...` with the default concurrency settings passed
  across the full yuhaiin repository. The `GOMAXPROCS=4` failure above is a
  separately reproduced existing test deadlock, not a passing full-suite claim.
- CI's `golangci-lint v2.14.0 run --timeout=5m` and `go fix ./...` were executed.
  `go fix` modernized one embedded-field composite literal to Go 1.27 syntax;
  a repeated run made no further changes. Lint reported `0 issues`. Formatting
  and `git diff --check` were also checked.

The cross-platform check builds the changed fork packages (`netns`, `tsdial`,
DNS, UDP relay, tsnet, magicsock) and the yuhaiin Tailscale package with
`CGO_ENABLED=0 go build` for Linux/amd64, macOS/arm64, Windows/amd64,
Android/arm64 and iOS/arm64. These are library compilation checks, not linked
mobile applications or runtime tests.

Unverified deployment scenarios: a production Tailnet/account or Headscale,
internet NAT/firewall traversal, actual remote SOCKS/other upstream UDP relay
semantics, production peer relay, routing-interface changes on real mobile/Apple
or Windows devices, and sustained throughput/latency under load. Local success
does not establish those capabilities.
