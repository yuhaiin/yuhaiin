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
- **MagicDNS:** A and AAAA answers for names known to lite's authorized NetMap
  are returned locally over both TCP and UDP at 100.100.100.100:53. Unknown
  or split-DNS names return REFUSED; they are never sent to a system resolver.
  Full Tailscale DNS forwarding, reverse DNS, service records, CNAME and
  search-domain compatibility must be addressed before production promotion.
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

A dedicated CI job repeats this runtime dependency check and executes the local
Control/DERP and lightweight TCP/UDP test. Test-only gVisor reference code can
remain for independent benchmarking, but it must not appear in shipping binaries.
