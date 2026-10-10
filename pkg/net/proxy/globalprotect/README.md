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
- Tunnel MTU uses the configured value or the gateway value; when both are
  zero, it is derived from the TLS TCP MSS (with OpenConnect's conservative
  base-MTU fallback where the socket MSS is unavailable).

**Not supported yet:** portal discovery, client certificates, SAML/SSO,
interactive MFA/challenges, HIP reports, ESP/UDP, IPv6 negotiation,
reauthentication after the authentication lifetime, applying gateway-pushed
DNS, split routes or local-network policy, and automatic reconnection. Gateways
requiring HIP or ESP are rejected with an explicit error. A gateway `<timeout>`
causes a TLS tunnel rekey 60 seconds before the timeout, or halfway through
shorter intervals. `<lifetime>` and `<disconnect-on-idle>` are enforced
separately. An expired authentication lifetime closes the tunnel and requires
a new login. This early version is not a replacement for the official
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
configuration, or apply the gateway's local-network policy. Configure split
routing and DNS explicitly in yuhaiin.

## Tests

```sh
go test ./pkg/net/proxy/globalprotect ./pkg/contract/node ./pkg/register
```

Unit tests cover tunnel frame validity, DPD, malformed frames, XML login and
configuration responses, unsupported SSO, and typed protocol JSON round-trip.
The in-process `TestGatewayEndToEndTCPUDP` starts a mock TLS Gateway and
a second gVisor IP stack, then exercises the full client lifecycle with TCP
and UDP echo traffic, followed by logout. This is a **mock-server integration
test**, not evidence of wire compatibility with a PAN-OS device. Real Gateway
interoperability still needs testing against authorized deployments.

## OpenConnect behavioral compatibility

The `openconnect_compat_test.go` cases are independently authored Go tests
inspired by OpenConnect's `tests/gp-auth-and-config` and
`tests/fake-gp-server.py`. They check the wire behavior used by OpenConnect's
fake Gateway: the JNLP login arguments, the matching `portal`, `domain`,
`authcookie`, and `preferred-ip` in the subsequent getconfig request, a
successful `<response>` without optional status/need-tunnel indicators, and
explicit unsupported errors for SAML and XML/JavaScript OTP challenges.
Missing optional indicators are accepted; explicitly negative indicators
continue to fail. No OpenConnect implementation or test source is vendored.

OpenConnect's fake Gateway intentionally refuses tunnel establishment, so it
cannot validate actual packet transport. Our separate Go in-process Gateway
drives TCP and UDP traffic through two gVisor stacks, but still isn't PAN-OS.

References:
- [PAN GlobalProtect protocol observations](https://github.com/dlenski/openconnect/blob/master/PAN_GlobalProtect_protocol_doc.md)
- [OpenConnect authentication test](https://gitlab.com/openconnect/openconnect/-/blob/master/tests/gp-auth-and-config)
- [OpenConnect fake GP server](https://gitlab.com/openconnect/openconnect/-/blob/master/tests/fake-gp-server.py)

OpenConnect tests are licensed under LGPL-2.1-or-later; using their scenario
ideas instead of copying their source keeps yuhaiin's test implementation
independent.
