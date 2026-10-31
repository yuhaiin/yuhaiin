# Tailnet compatibility rollback (2026-10-26)

This change restores the **tsnet.Server** transport and DNS integration that
preceded [#619](https://github.com/yuhaiin/yuhaiin/pull/619). The global
TUN inbound and the Yuhaiin Tailnet application TCP/UDP stack **remain lightweight**.
Only the embedded Tailscale control / DNS integration is rolled back.

## Reason for rollback

A live Tailnet reported repeated A/AAAA DNS timeouts for
`5600g.taild2025.ts.net.` and unsuccessful UDP DNS initialization against
`100.100.100.100:53`. The lite adapter gates even local service DNS on
`WaitTransportReady`, which waits for control-reported endpoint/DERP state;
its DNS map and forwarding behavior also differs from the known-working tsnet
implementation. The logs alone cannot establish which DNS path ultimately
caused the resolver deadline, so retaining the regression is not justified.

## What is restored

- The existing `tsnet.Server` start / `Up` lifecycle and Tailscale
  `UserDialPlan` route / name resolution.
- The existing Tailscale DNS Manager for TCP and UDP at
  `100.100.100.100:53`, including MagicDNS, reverse lookups, Split DNS and
  control-configured upstreams.
- Persistent per-node state path, custom Yuhaiin Underlay, recursive dependency
  detection, fail-closed Tailnet-only routing, and lightweight userspace
  TCP/UDP sockets.
- The release Tailscale feature set that tsnet actually needs. Tests retain
  both service-DNS wire transports and real local encrypted peer traffic.

No global gVisor / tun2socket TUN backend is reintroduced. The `tsnet`
dependency itself may transitively link Tailscale's own netstack / gVisor
packages; do not mistake that for a re-enabled Yuhaiin legacy TUN backend.

## State and rollback considerations

The lite migration originally preserved the legacy `tailscaled.state`
file. Restoring tsnet uses that file without changing Tailnet node identity.
Keep the existing data directory. Do **not** delete `lite.json` or the
previous legacy state files until live connectivity is confirmed.

A brand-new Tailnet identity enrolled **only** by lite may not have a usable
legacy `tailscaled.state`. This rollback cannot automatically import that
identity into tsnet. Back up the state directory and verify enrollment first;
re-registering with an auth key may create a distinct Tailscale node.
The old and new state files must not be concurrently opened by two runtimes.

## Validation / release gate

```sh
go test ./cmd/buildtags ./pkg/net/proxy/tailscale/...
go test -count=1 -run 'TestLocalTailnet' ./pkg/net/proxy/tailscale
tags="$(go run ./cmd/buildtags/...)"
go test -count=1 -tags="$tags" -run 'Test(DNSPacket.*|TailscaleDNSManagerMissing|UnavailableTailscaleDialer)$' ./pkg/net/proxy/tailscale
go build -tags="$tags" ./cmd/yuhaiin
```

Live validation must separately exercise A and AAAA responses from the actual
Tailnet, TCP/UDP service DNS, Split DNS, Tailnet peer TCP/UDP, expiry /
reconnect and the configured upstream dialer. Tests alone do not establish
production Tailnet / Headscale compatibility.
