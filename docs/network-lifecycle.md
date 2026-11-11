# Network lifecycle and selective recovery

Routing state, network identity, and socket validity have separate lifetimes.
`DefaultRouter` still follows routing-table changes. `AddNetworkMonitor` retains
its existing interface/address/gateway notification semantics. Neither callback
is a connection invalidation signal.

The existing platform monitor also publishes complete interface observations to
`pkg/net/netstate`. Its typed events distinguish `RouteChanged`, `NetworkChanged`
and `ConnectivityChanged`. A route, gateway, priority, DNS setting, or notification
count is never an identity. Unknown/failed observations retain the previous view.
An unknown selected underlying network also cannot prove a switch.

## Identity and ownership

* Linux uses ifindex within the monitor's network namespace. Link deletion/down
  and address deletion retire tokens immediately, before route debounce can hide
  a delete/recreate cycle. Netlink address flags exclude failed DAD and
  non-optimistic tentative sources while keeping deprecated/optimistic usable
  sources. Interface names are binding/diagnostic metadata.
* Windows uses interface LUID, interface/address callbacks, and complete address
  reconciliation. IP-interface deletion is scoped to its family, rather than
  treated as removal of the whole adapter. Complete IP-interface and unicast
  address rows filter disconnected families and invalid/tentative/duplicate
  sources; deprecated usable addresses remain valid. Removing an IPv4 source
  does not retire an IPv6 source.
* macOS uses interface index, interface/address route-socket messages, and actual
  local source addresses. Existing default/underlying-interface selection is
  preserved; a route-socket message or stale utun delegation alone proves nothing
  about socket validity.
* Android has a `network.report` C ABI operation (`ReportUnderlyingNetworks`) for non-VPN
  `ConnectivityManager.Network` handles, capabilities and `LinkProperties`.
  Validation and DNS settings do not participate in identity. The Android
  companion observes all matching networks separately from best-network
  selection: losing a best match is not necessarily losing a usable network.
  Its API 24/25 callback registration retains the older overload. Protection
  continues through the application's existing socket-protect callback. An optional
  outbound-only native binder then calls `Network.bindSocket` and reports the
  handle actually bound to that fd. Pending and established resources use this
  handle, rather than assuming the VPN underlay hint also binds sockets.
  Unobserved handles never borrow another Network's identical source address.

A resource captures a network-lifetime token and, when known, its actual source
address or usable address-family token. Generations describe confirmed changes;
connections are **not** invalidated by comparing to a global generation. Renaming
an interface is harmless. A source address removed and subsequently re-added gets
a fresh token. Address additions preserve existing sockets. For wildcard UDP,
partial address churn cannot prove which source was used: only replacement of
all previous sources in the relevant family, or interface loss, retires it.

Registration and unregistration happen at connection creation/close, never for
each packet. Snapshots are immutable. A single shared monitor and cleanup worker
serve core instances; the final monitor owner waits for shutdown before restart.
Callbacks execute outside monitor/route/registry locks. Cleanup is dispatched in
batches of at most 64 registrations without a goroutine per ordinary connection.
An obsolete callback captures its original resource, not a mutable owner slot.
Protocol workers check current invalidation state so coalesced stale notifications
cannot lose a newer invalidation or retire a healthy replacement.

## Resource behavior

The direct TCP dialer cancels affected pending attempts and retains the actual
local source after connect. Established direct and proxy-carrier TCP sockets are
closed only after their known path is invalid. There is no stream replay or
application-data retry. The returned `dialer.TCPConn` embeds `net.TCPConn`, retaining
half-close, socket options, syscall and copy capabilities; callers explicitly
naming the previous concrete return type must use the new wrapper type.

Outbound UDP wrappers similarly preserve native UDP/OOB/buffer/syscall methods.
Inbound listeners opt out. Closing an affected UDP socket wakes its existing NAT
reader. The existing source owner retires that socket and creates a replacement
on demand; unaffected full-cone sockets and mappings stay in place. There is no
NAT-table purge or destination-based session split.

DNS UDP queries belong to the exact pooled socket on which they were sent.
Failure of that socket releases its queries and upstream admission permits;
old reader teardown cannot clear a replacement pool or cancel its queries.
TCP/TLS DNS queries and HTTP/QUIC DNS transports observe their underlying
carrier failure. Healthy cache entries, FakeIP mappings, singleflight ownership,
and the admission/cache-hit separation from #672/#674 are retained. HTTP pools
retire their affected underlying connections through ordinary read/close handling;
unrelated transports are not rebuilt and valid active streams are untouched.

## Protocol-specific recovery

| Transport | Behavior on a confirmed affected path |
| --- | --- |
| WireGuard | Native `Device.BindUpdate`, retaining device, keys, peers and inner stack/streams. Only the outer socket is replaced. Failed/unidentifiable rebinds retry with a bounded timer. |
| Tailscale, direct underlay | Notify the owning instance's native magicsock `Rebind`. Preserve tsnet/netstack identity. Native netmon ownership and upstream-proxy behavior remain in place. Already-closed old sockets cannot trigger another rebind. |
| Hysteria2 configured address/port hopping | Wake the existing hop worker immediately and swap its socket, preserving the QUIC session and streams. Failed socket opens retry; old path cleanup is scoped to its socket. |
| Hysteria2 without hopping / ordinary QUIC | Close only an obsolete underlying socket. Existing session failure/lazy reconnect policies apply. No unnegotiated `AddPath` call; the Hysteria2 profile uses zero-length local CIDs and disables the QUIC path manager. |
| IKEv2 UDP with negotiated MOBIKE | Call the existing session `Roam`, reuse protection/binding on initial, floated and replacement sockets, retain SAs/ESP pump/inner stack, and resubscribe to the new local source. Failed roaming retries every five seconds until shutdown/recovery. |
| IKEv2 TCP or UDP without MOBIKE | Do not invoke MOBIKE. A known obsolete carrier can close; session re-establishment is not added here. |
| MASQUE | Retire an affected H2/H3 carrier and use its existing reconnect loop/retained packet stack. Native QUIC path migration is not added. |
| GlobalProtect, OpenVPN, SoftEther, L2TP | Existing protocol-owned failure/reconnect/authentication/backoff and `auto_reconnect` policies handle carrier failure. No forced node-wide restart or new session-resumption capability is introduced. Existing supervisors can rebuild a failed session's stack as before. |

An unaffected proxy tunnel's inner connections do not inherit a new affinity just
because the host's default route changed. Native migration keeps its owner alive;
reconnect-only protocols retain their existing limits on inner-stream survival.

## Observability and conservative limits

`yuhaiin_network_lifecycle_events_total` has fixed `kind` values: `route_only`,
`transition`, `duplicate`, `resource_invalidation`, `dns_cancellation`,
`recovery_attempt`, `recovery_success`, and `recovery_failure`. No IP, interface
name, domain, or connection ID is a label. Recovery success means the native
operation completed, not a general Internet reachability guarantee; magicsock's
void `Rebind` API only records dispatch attempts. Confirmed changes log evidence,
source, generation and (for individual authoritative callbacks) interface index.
Routine route notifications do not produce info logs.

If platform identity, a socket's binding, or a complete address observation is
unavailable, resources remain untracked rather than guessing from routes.
Wildcard UDP with multiple remaining possible source addresses is deliberately
conservative. A layer-2 replacement that retains the same OS interface identity,
addresses and liveness without an authoritative signal cannot be inferred on
desktop platforms. An unobserved interface lifetime entirely between snapshots
also cannot be inferred from route metadata. Android needs the companion's native
bridge to distinguish replacement Networks that reuse an interface and IP.

The monitor is scoped to its own namespace. Custom namespace dialers, external
sockets, and opaque proxy resources without reliable host-source affinity are
not globally adopted or destroyed. There are no per-packet network queries,
route parsing, state polling, global packet locks, cache flushes, inbound restarts,
or forced resets of unrelated VPNs.

## Verification

Deterministic injected snapshots and fake owners cover route-only storms,
metadata/route churn, temporary discovery failure, interface/source loss and
recreation, renaming, renewal, independent address families/networks, unknown
selection, rapid A/B/A, registration/close races and shared-monitor shutdown.
Local TCP/UDP/DNS integration tests verify prompt old-path cancellation,
admission release, preserved cache/unaffected queries, stale-dial rejection,
selective full-cone socket replacement, and native WireGuard/Hysteria2 recovery
with an existing encrypted inner TCP stream. IKE setup cancellation hands the
creation token to the established session without keeping obsolete setup
subscriptions. IKE tests cover setup cancellation/ownership transfer, negotiation gating,
coalescing, current-socket selection and shutdown during retry.

The Android companion is a separate PR and builds against the new core AAR.
Android CI normally consumes an AAR from core main; the companion therefore
requires this core change to be released/built before its normal CI dependency
selection can include the bridge. Local validation uses an AAR generated from
this branch. Real Wi-Fi/cellular switching and live IKEv2 MOBIKE interoperability
are not claimed by the deterministic tests or cross-compilation.

Reproducible microbenchmarks and executed checks are recorded in
[benchmarks/network-lifecycle.md](benchmarks/network-lifecycle.md).
