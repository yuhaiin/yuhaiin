# GlobalProtect SSL outbound (experimental)

This is a **direct GlobalProtect gateway** outbound, implemented in Go without
CGO, OS TUN, or new module dependencies. It uses yuhaiin's existing gVisor
IP stack (the same one used by WireGuard) to expose TCP and UDP connections.

## Scope

- Username/password login against `/ssl-vpn/login.esp`
- Gateway prelogin (rejects SAML/SSO), cookie and `getconfig.esp`
- Authenticated SSL IP tunnel, IPv4, DPD/keepalive, TCP/UDP via gVisor
- Validates server certificates against the system trust store, optionally
  extended by a PEM certificate authority. There is no insecure TLS flag.
- Tunnel MTU defaults to 1300 when the gateway returns zero.

**Not supported yet:** portal discovery, client certificates, SAML/SSO,
interactive MFA/challenges, HIP reports, ESP/UDP, IPv6 negotiation, automatic
rekey/reauthentication, applying gateway-pushed DNS/split routes, and automatic
reconnection. If the gateway requires these features, this outbound may not
connect. A tunnel lifetime returned by the gateway is enforced: when it
expires, the tunnel closes with an explicit error instead of continuing with
expired credentials. This early version is not a replacement for the official
enterprise-managed endpoint client.

## Node example

```json
{
  "id": "gp-1",
  "name": "Enterprise VPN gateway",
  "origin": "manual",
  "enabled": true,
  "chain": [
    {
      "type": "globalprotect",
      "globalprotect": {
        "gateway": "vpn.example.com",
        "username": "alice",
        "password": "YOUR_SECRET",
        "mtu": 1300
      }
    }
  ]
}
```

The `gateway` is the gateway hostname (optional HTTPS scheme and TCP port).
It must not be a portal URL with a path. `ca_cert_pem` is an optional PEM
bundle for gateways using a private enterprise certificate authority. The
optional `computer` field identifies the local device during login/logout.

The current UI may require raw contract/API configuration until a dedicated
frontend editor is added. Credentials are saved with the node using the
existing yuhaiin node-store security model; protect exports/backups.

The outbound does not automatically replace yuhaiin's own routing or DNS
configuration. Configure split routing and DNS explicitly in yuhaiin.

## Tests

```sh
go test ./pkg/net/proxy/globalprotect ./pkg/contract/node ./pkg/register
```

Unit tests cover tunnel frame validity, DPD, malformed frames, XML login and
configuration responses, unsupported SSO, typed protocol JSON round-trip, and
a local TLS tunnel handshake. Real gateway interoperability still needs
testing against authorized GlobalProtect deployments.

Protocol reference:
[PAN GlobalProtect protocol observations](https://github.com/dlenski/openconnect/blob/master/PAN_GlobalProtect_protocol_doc.md).
