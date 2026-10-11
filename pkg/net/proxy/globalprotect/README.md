# GlobalProtect SSL/ESP outbound (experimental)

This is a **direct GlobalProtect gateway** outbound, implemented in Go without
CGO, OS TUN, or new module dependencies. It uses yuhaiin's existing gVisor
IP stack (the same one used by WireGuard) to expose TCP and UDP connections.

## Scope

- Username/password login against `/ssl-vpn/login.esp`
- Gateway prelogin (rejects SAML/SSO), cookie and `getconfig.esp`
- Authenticated SSL IP tunnel, IPv4, DPD/keepalive, TCP/UDP via gVisor
- Automatic reconnection after an established tunnel drops, with capped
  exponential backoff
- Validates server certificates against the system trust store, optionally
  extended by a PEM certificate authority. `insecure_skip_verify` is an
  explicit opt-in for gateways whose certificate cannot be verified.
- Tunnel MTU uses the configured value or the gateway value; when both are
  zero, it is derived from the TLS TCP MSS (with OpenConnect's conservative
  base-MTU fallback where the socket MSS is unavailable).

**Not supported yet:** portal discovery, client certificates, SAML/SSO,
interactive MFA/challenges, HIP reports, IPv6 negotiation, applying
gateway-pushed DNS, split routes or local-network policy. Gateways requiring
HIP are rejected with an explicit error. A gateway `<timeout>` causes a TLS
tunnel rekey 60 seconds before the timeout, or halfway through shorter
intervals. `<lifetime>` and `<disconnect-on-idle>` are enforced separately.
When the active TLS tunnel drops or its authentication lifetime expires, the
client starts a fresh login and retries until it reconnects or the node is
closed. Retry delays grow from 1 second exponentially up to 60 seconds, with
jitter to avoid synchronized retries. A gateway-requested idle disconnect
waits for the next connection request before logging in again. Initial
connection failures still return an error to the caller. If a reconnect is
rejected or requires interactive authentication, automatic retries stop to
avoid repeating login attempts; close and reopen the node after fixing the
credentials or authentication requirement. Missing DPD responses are treated
as a tunnel failure after 30 seconds, even when the underlying TCP connection
has not reported an error. This early version is not a replacement for the
official enterprise-managed endpoint client.

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
bundle for gateways using a private enterprise certificate authority. Set
`insecure_skip_verify` to `true` to disable certificate-chain and hostname
verification; it is `false` by default. The optional `computer` field identifies
the local device during login/logout.

The default remains SSL. Set `use_esp` to `true` to try the gateway's ESP-over-UDP
path first. Supported suites are AES-128/256-CBC with HMAC-SHA1-96 or
HMAC-SHA256-128; unsupported keying or failed activation falls back to SSL.
Three authenticated activation probes bound UDP discovery to six seconds.
Opening SSL happens after those probes because it may invalidate the ESP keys.
Replay/tamper checks precede delivery to gVisor; sequence exhaustion fails closed.
The gateway's HTTPS configuration supplies the ESP keys. ESP supplies no
independent key exchange or forward secrecy. With ESP, gateway timeout forces a
fresh login/session before the key lifetime ends. Both transports honor the
preceding outbound proxy; a proxy that cannot carry UDP triggers SSL fallback
through that same proxy, without an unproxied UDP dial.

`data_transport` in gateway extra info identifies the active `ssl` or `esp` path.
The ESP simulator verifies activation, authenticated TCP/UDP egress, replay and
tamper rejection, and SSL fallback when UDP is blocked. This is not evidence of
PAN-OS interoperability. The activation/keying layout was adapted from
[xen0bit/veepin](https://github.com/xen0bit/veepin/tree/810e017596c0b5b55bc0da563929bde13a6b201d/internal/gp)
(MIT); see [license](ESP_THIRD_PARTY_LICENSE).

Compared with that reference, the missing outbound feature was ESP/UDP; its
server/listener API is outside this outbound's scope. Neither client implements
portal discovery, SAML, client certificates, HIP submission or negotiated IPv6.
Yuhaiin additionally enforces idle/auth lifetimes, reconnect and route-info API.

The web node editor includes a GlobalProtect configuration form. After the
node has connected, its editor can load the last gateway configuration
returned by `getconfig`, including assigned address, routes, DNS, and the
local-network policy. This reads the active runtime instance and does not
start or retry a connection. Credentials are saved with the node using the
existing yuhaiin node-store security model; protect exports/backups.

The outbound does not automatically replace yuhaiin's own routing or DNS
configuration, or apply the gateway's local-network policy. Configure split
routing and DNS explicitly in yuhaiin.

For latency checks against an internal service reachable through this tunnel,
set a per-node HTTP/HTTPS latency URL. TCP Ping sends its HTTP request through
the node's outbound chain. The URL override and optional per-node TLS
verification setting are documented in [node configuration](../../../../docs/node.md#per-node-latency-target).

## Tests

```sh
go test ./pkg/net/proxy/globalprotect ./pkg/contract/node ./pkg/register
```

Unit tests cover tunnel frame validity, DPD, malformed frames, XML login and
configuration responses (including route lists), unsupported SSO, and typed
protocol JSON round-trip. Runtime and API tests verify gateway information is
available only from the active cached outbound.
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
