# tailscale-lite outbound

`tailscale-lite` is an opt-in outbound alongside the existing `tailscale`
outbound. `tailscale` continues to use `tsnet.Server`. Both expose Tailnet
TCP/UDP through Yuhaiin's lightweight application stack and use the configured
upstream for control, DERP and UDP discovery/transport.

Create a node with a `tailscale-lite` protocol layer in the node editor, or use:

```json
{
  "id": "tailnet-lite",
  "name": "Tailnet Lite",
  "origin": "manual",
  "enabled": true,
  "chain": [
    {
      "type": "tailscale-lite",
      "tailscale-lite": {
        "hostname": "yuhaiin-lite",
        "auth_key": "tskey-auth-REPLACE",
        "control_url": "",
        "debug": false
      }
    }
  ]
}
```

An empty `control_url` selects Tailscale's default control server. Supply the
Headscale control URL when using Headscale. The authentication key is secret.
As with `tailscale`, insert upstream protocol layers using the normal node
chain when control and transport must use another outbound.

## Independent identities

Lite stores its identity in `tailscale-lite/v1-<opaque-id>/lite.json` under the
data directory. tsnet retains its existing `tailscale` directory. Choosing lite
creates a separate Tailnet node, even when the hostname, key and control URL
match an existing tsnet configuration. It does not migrate or overwrite tsnet
state. Both types can run together; switching types is an explicit configuration
change and may require a new usable enrollment key.

Closing one outbound leaves the other alive. Reopening the same lite
configuration reuses its own persisted identity. Full recovery includes the
configured lite identity; clone recovery disables the outbound and excludes
machine identity files, following the existing native VPN recovery policy.
Configuration-only exports redact the authentication key.

## DNS and readiness

UDP/TCP requests to `100.100.100.100:53` and `[fd7a:115c:a1e0::53]:53` are handled
by the embedded DNS manager. It supplies MagicDNS, ExtraRecords, reverse PTR,
split/default forwarding and control updates. IPs returned for application
connections must still match an authorized Tailnet route; DNS answers cannot
turn an external destination into direct access.

Local DNS waits for an authorized, applied NetMap. It does not wait for a
control server to echo the local `HomeDERP` or `Endpoints`, or for the first
peer handshake. This avoids the DNS socket timeout regression from #619.
Peer connections still depend on working discovery/DERP, peer availability and
ACLs; control readiness alone is not evidence of a working peer session.

Background monitoring only inspects cached status and does not create a new
client or identity. Underlay recursion checks apply across both outbound types.
Tailnet Lock remains unsupported by lite and is rejected by the dependency.
The tsnet outbound remains available for compatibility.

## Validation

Local tests use a control server, DERP/STUN fixtures and real encrypted traffic;
they require no production credentials. Coverage includes:

- Lite-to-lite IPv4/IPv6 TCP/UDP, with and without STUN.
- DNS over UDP/TCP, A/AAAA/PTR, ExtraRecords, split/default DNS, live updates,
  authoritative negative answers, route denial and revocation.
- DNS while the control server omits self transport information.
- Lite and tsnet with identical configuration running independently, exchanging
  TCP/UDP in both directions, and preserving identity across lite restart.
- Registration, background monitoring, recovery, clone isolation and rollback.

```sh
go test -race -count=1 ./pkg/net/proxy/tailscale ./pkg/contract/node ./pkg/node ./pkg/app/backup/recovery
```

These fixtures do not replace acceptance testing against a deployed official
Tailnet or Headscale, including provider DNS policy and network reconnection.
