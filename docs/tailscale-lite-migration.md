# Lightweight-only TUN and tailscale-lite migration

This change removes the two legacy global TUN backends:
`pkg/net/proxy/tun/gvisor` and `pkg/net/proxy/tun/tun2socket`.
The global TUN inbound now constructs `lightweighttun.New` for both new and
persisted configurations. The historic `system_gvisor` and `fdbased` driver
values are normalized to `channel`; congestion control and scheduler continue
to be configured on the lightweight core. IPv4-only links retain MTUs down to
576; active IPv6 addresses still require at least 1280.

## Tailnet outbound

`pkg/net/proxy/tailscale` now embeds
[`github.com/yuhaiin/tailscale-lite`](https://github.com/yuhaiin/tailscale-lite/pull/1)
for control coordination, peer routing, ACL filters and WireGuard/magicsock
encryption. The adapter supplies the same per-node `Underlay` that routes
control HTTP/Noise, DERP TCP and UDP/STUN through the configured Yuhaiin
outbound. **RequireUnderlay is always true**. The network payload path is
`wireguard.LightweightNetTun`, not a Tailscale netstack or OS interface.

## Compatibility and validation coverage

- **Legacy node identity:** `tsnet` stores a `tailscaled.state` profile
  database; lite uses `lite.json`. On upgrade, `MigrateLegacyState` imports
  the selected machine and node private keys from a private legacy file into
  the new state format, checking the selected profile and control URL.
  It preserves the original state for rollback and never overwrites an
  existing lite identity. Ambiguous, logged-out, malformed, insecurely
  permissioned or cross-control identities fail closed instead of
  automatically registering another Tailnet node. The converter reads the actual
  `ipn.Prefs` identity field (`Config`), not a synthetic `Persist` field. A local
  enrolled-tsnet -> lite -> tsnet rollback test preserves the machine/node keys,
  node ID, addresses and original legacy file. Unix permissions and Windows
  owner/DACL checks protect persisted state; native Windows CI exercises reload
  and migration.
- **DNS compatibility:** The lite engine now reuses the existing Tailscale
  DNS Manager and rebuilds its resolver configuration on every authorized
  NetMap: MagicDNS, A/AAAA/PTR, ExtraRecords, search domains, Split DNS routes,
  and default resolvers. Queries to 100.100.100.100:53 work over TCP and UDP.
  DNS to routable Tailnet peers uses the injected lightweight stack; other
  configured resolvers use this instance's host-provided Underlay, not an
  untracked system socket. DNS-assisted outbound hostnames also use this
  manager and are restricted to validated Tailnet routes. Tests exercise
  local DNS and Split/default forwarding; live Tailscale/Headscale provider
  combinations and special DNS record handling still need acceptance tests.
- **Tailnet Lock:** lite currently fails closed for unsupported TKA. This means
  Tailnet Lock-enabled tailnets will not connect.
- **Control-plane reconnection:** local tests cover logout/revocation and key
  expiry without another control update, including removal of engine peers,
  route ownership and full DNS responses. Renewal invalidates old timers.
  Initial endpoint discovery/rebind completes before exposing transport readiness;
  later periodic probes do not delay new sockets. Mobile underlay changes and
  provider-specific reconnection policies remain deployment acceptance cases.
- **IPv6:** the local two-node tests exchange TCP and UDP over both assigned
  address families and verify MagicDNS AAAA, with working and unavailable STUN.
- **Security:** if a DNS query or destination cannot be validated against
  the authorized NetMap, no system-network fallback is permitted.
- **UI:** yuhaiin-react #531 removes legacy choices and normalizes saved values.
  The companion MTU regression verifies that editing an old configuration keeps
  a saved IPv4 MTU of 1200.

The dependency, backend and frontend checks must pass before merging. Automated
coverage uses real tsnet persistence and encrypted transport against local
control/DERP/STUN services; it does not claim acceptance against every deployed
Tailscale or Headscale policy.

## Validation

```sh
go test ./pkg/net/proxy/tailscale ./pkg/net/proxy/tun/... ./cmd/buildtags ./cmd/android
tags="$(go run ./cmd/buildtags/...)"
go list -deps -tags="$tags" ./cmd/yuhaiin ./cmd/android | grep -E '^(gvisor.dev/gvisor|tailscale.com/tsnet)' && exit 1
```

A dedicated CI job repeats this runtime dependency check under the shipping
build tags, then separately runs the full local Control/DERP integration without
the release-only Tailnet Lock omission tag (the test-control package itself
requires the TKA test APIs). This avoids linking TKA into production binaries
just to compile integration tests.

The two-node integration currently verifies encrypted lightweight TCP/UDP,
MagicDNS A/AAAA, IPv4/IPv6 peer TCP/UDP, PTR,
control-provided ExtraRecords (A and AAAA), Split DNS and default upstream
forwarding, DNS over TCP, split-DNS name resolution to a Tailnet peer, live
ExtraRecord updates without restarting, prevention of authoritative MagicDNS
leaks, per-node Underlay use, denial of out-of-Tailnet DNS-assisted routes, and
revocation of route/DNS authorization when the control plane expires a node.

**Provider-specific acceptance remains:** production Tailscale/Headscale login,
key renewal and mobile reconnection should be checked in the target environment.
DNS forwarding to an actual Tailnet-hosted nameserver, DoH upstream variants,
full search-suffix semantics, and OS-specific DNS behavior still need targeted
tests. These checks do not establish complete compatibility with every Tailscale
DNS configuration. Test-only tsnet/gVisor references remain for migration, interoperability and
benchmark comparisons, but
must not appear in shipping binaries.
