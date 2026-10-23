# Lightweight-only TUN and tailscale-lite migration

This change removes the two legacy global TUN backends:
`pkg/net/proxy/tun/gvisor` and `pkg/net/proxy/tun/tun2socket`.
The global TUN inbound now constructs `lightweighttun.New` for both new and
persisted configurations. The historic `system_gvisor` and `fdbased` driver
values are normalized to `channel`; congestion control and scheduler continue
to be configured on the lightweight core.

## Tailnet outbound

`pkg/net/proxy/tailscale` now embeds
[`github.com/yuhaiin/tailscale-lite`](https://github.com/yuhaiin/tailscale-lite/pull/1)
for control coordination, peer routing, ACL filters and WireGuard/magicsock
encryption. The adapter supplies the same per-node `Underlay` that routes
control HTTP/Noise, DERP TCP and UDP/STUN through the configured Yuhaiin
outbound. **RequireUnderlay is always true**. The network payload path is
`wireguard.LightweightNetTun`, not a Tailscale netstack or OS interface.

## Known compatibility work before merge

- **Legacy node identity:** `tsnet` stores a `tailscaled.state` profile
  database; lite uses `lite.json`. On upgrade, `MigrateLegacyState` imports
  the selected machine and node private keys from a private legacy file into
  the new state format, checking the selected profile and control URL.
  It preserves the original state for rollback and never overwrites an
  existing lite identity. Ambiguous, logged-out, malformed, insecurely
  permissioned or cross-control identities fail closed instead of
  automatically registering another Tailnet node.
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
- **Control-plane reconnection:** exercise logout/revocation, key renewal,
  transient DERP disconnects, underlay rebinds and multi-node isolation.
- **IPv6:** exercise IPv6 peer TCP/UDP, DERP fallback and MagicDNS, not only
  successful address assignment.
- **Security:** if a DNS query or destination cannot be validated against
  the authorized NetMap, no system-network fallback is permitted.
- **UI:** separate yuhaiin-react settings may still expose legacy choices.
  The backend always uses lightweight regardless of those saved choices.

This integration is a **Draft PR**, not an approved release. Identity
migration now has synthetic-fixture tests, but it still requires a real existing
tsnet profile migration test against a live tailnet and rollback validation.
The full test matrix must pass before merging.

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
MagicDNS A and (if the simulated control allocates IPv6) AAAA, PTR,
control-provided ExtraRecords (A and AAAA), Split DNS and default upstream
forwarding, DNS over TCP, split-DNS name resolution to a Tailnet peer, live
ExtraRecord updates without restarting, prevention of authoritative MagicDNS
leaks, per-node Underlay use, denial of out-of-Tailnet DNS-assisted routes, and
revocation of route/DNS authorization when the control plane expires a node.

**Still require real Tailnet/Headscale acceptance:** the simulated test-control
server allocates only IPv4 node addresses, so IPv6 *peer* DNS and TCP/UDP
reachability are not yet validated (the AAAA ExtraRecord test is separate).
DNS forwarding to an actual Tailnet-hosted nameserver, DoH upstream variants,
full search-suffix semantics, and OS-specific DNS behavior still need targeted
tests. These checks do not establish complete compatibility with every Tailscale
DNS configuration. Test-only gVisor references may remain for benchmarks, but
must not appear in shipping binaries.
