# SoftEther native SSL-VPN outbound (experimental)

This implementation connects to **SoftEther's native SSL-VPN protocol**, not
Microsoft SSTP or OpenVPN compatibility mode. It is implemented in Go without
CGO, an external `vpnclient` process, or an operating-system TAP interface.

The native wire codec (TLS handshake, HTTP PACK control messages, SHA-0 password
challenge-response, Ethernet block records) is adapted from
[xen0bit/veepin](https://github.com/xen0bit/veepin), licensed MIT.
Its complete copyright and license terms are retained in
[`native/THIRD_PARTY_LICENSE`](native/THIRD_PARTY_LICENSE).

## Node configuration

```json
{
  "id": "softether-1",
  "name": "SoftEther native SSL VPN",
  "origin": "manual",
  "enabled": true,
  "chain": [
    {
      "type": "softether",
      "softether": {
        "gateway": "vpn.example.org:443",
        "username": "alice",
        "password": "YOUR_PASSWORD",
        "hub": "DEFAULT",
        "mtu": 1400
      }
    }
  ]
}
```

- `gateway`: TCP hostname or IP, optionally followed by `:port` (443 default);
  do not supply `https://` or a URL path.
- `hub`: virtual HUB; defaults to `DEFAULT`.
- The client sends DHCP DISCOVER/REQUEST and needs a valid DHCP router on the
  virtual Ethernet segment. SecureNAT or a bridged LAN DHCP server can supply it.
  It does **not** use an IP address in the SoftEther login welcome.
- To disable DHCP, supply **both** `address` (IPv4 CIDR, e.g.
  `192.168.30.5/24`) and `router` (`192.168.30.1`).
- The server's TLS certificate is checked against system roots by default.
  `ca_cert_pem` adds a private CA PEM. `insecure_skip_verify: true` opts out
  of certificate verification and exposes the login to impersonation attacks.
- `mtu` defaults to 1400; allowed range is 576–1500. Currently IPv4 only.
- The underlying connection can use an earlier proxy in the yuhaiin chain.
  TCP and UDP application connections use yuhaiin's existing gVisor user stack,
  not an OS TAP interface.

## Limitations

This early implementation supports one TLS/TCP session, username/password
login, virtual Ethernet, DHCP or static IPv4, and IPv4 TCP/UDP via one resolved
gateway MAC. It does **not** implement UDP Acceleration, multiple TCP channels,
certificate/SSO authentication, IPv6, dynamic reconfiguration, or reconnecting
an interrupted session. The connection fails closed when the TLS data path
fails. This first version is for routed VPN egress through SecureNAT or a
reachable IPv4 gateway; arbitrary on-link L2 peer discovery is not supported.

No OS-wide kill switch or split-route policy is installed by this outbound.
The TunnelCrack advisory requires additional consideration at the OS-routing /
policy layer; adding an SSL VPN protocol is not equivalent to a leak-proof VPN.

## Tests

```sh
go test ./pkg/net/proxy/softether/... ./pkg/contract/node ./pkg/register
```

The native codec unit tests are adapted from veepin's MIT suite. The additional
tests cover malformed/truncated DHCP replies, ARP, server address parsing, and
typed node config roundtrips.

For a **real SoftEther** compatibility test, provision a SoftEther Server
with a `DEFAULT` virtual hub, a password user, SecureNAT or bridge-attached DHCP,
and a valid server certificate (or explicitly enable the insecure option in a
throwaway test environment). A reference Docker setup and `vpncmd` provisioning
commands are available in
[veepin's SoftEther interop test](https://github.com/xen0bit/veepin/blob/main/tests/interop/compose.softether.yml).
The attached unit tests do not by themselves prove interoperability with every
release of the official server.
