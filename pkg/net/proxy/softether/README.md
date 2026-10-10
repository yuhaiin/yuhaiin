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

## Extended authentication, IPv6, UDP and reconnect

- `auth_type: "password"` (default) uses the historical SHA-0 challenge-response.
- `auth_type: "certificate"` requires `client_cert_pem` and
  `client_key_pem` containing a matching RSA X.509 certificate and RSA
  private key. It uses SoftEther's native RSA/SHA-1 challenge signature
  (not mutual TLS). The private key is stored in node settings: protect
  exports and backups. The server must grant certificate login to that user.
- `ipv6_address: "2001:db8:30::25/64"` and `ipv6_router: "fe80::1"`
  enable a second gVisor IPv6 protocol address and in-memory ICMPv6 neighbor
  discovery. IPv6 forwarding requires both values and MTU >= 1280.
  Automatic SLAAC, router advertisements, DHCPv6, IPv6 DNS and address
  reconfiguration are **not** implemented.
- `udp_acceleration: true` requests the native encrypted UDP Acceleration
  **v2** channel (ChaCha20-Poly1305). UDP acceleration needs a direct UDP
  transport path and cannot be chained through a TCP-only upstream proxy.
  Only authenticated UDP Ethernet frames are accepted; the tunnel remains
  on TLS if the peer does not negotiate compatible v2 or acknowledgments stop.
  Legacy v1/RC4 and NAT-T relay discovery are not implemented.
- `auto_reconnect: true` reconnects a failed TLS session with bounded
  exponential backoff, rebuilding DHCP/static address, ARP/NDP and the
  userspace gVisor network. New TCP/UDP connections wait for the replacement
  session. Existing live TCP/UDP sockets are **not** migrated.

## Limitations

This is experimental, pending official SoftEther VPN Server interoperability
validation of all four extended modes. It does not implement SSO,
hardware-backed private keys, multiple parallel TCP channels, full generic
layer-2 bridging, automatic IPv6 configuration, or server-pushed DNS and
split-route policy. Only a virtual gateway (or SecureNAT) path is supported.
The client fails closed when transport is unavailable and does not use a
direct bypass in place of a failed VPN tunnel.

No OS-wide kill switch or split-route policy is installed by this outbound.
The TunnelCrack advisory requires additional OS-routing and policy defenses;
adding a protocol is not equivalent to a leak-proof VPN.

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

The real-server test also enables UDP acceleration to cover the direct UDP
setup path; when the container network cannot reach the server's UDP endpoint,
application UDP remains on the TLS fallback. The sustained TCP benchmark sends
16 MiB per iteration while the peer echoes it, and reports one-way application
throughput:

```sh
echo_ip="$(podman compose -f pkg/net/proxy/softether/testdata/compose.yml exec -T echo hostname -i | awk '{print $1}')"
env SOFTETHER_GATEWAY=127.0.0.1:14443 SOFTETHER_ECHO_IP="$echo_ip" \
  go test -tags=softether_interop -run '^$' \
  -bench '^BenchmarkOfficialSoftEtherTCPSustained$' -benchtime=5x \
  ./pkg/net/proxy/softether
```

To test lease renewal against a short lease, start the fixture with
`podman compose -f pkg/net/proxy/softether/testdata/compose.yml up -d server echo`,
then run:

```sh
podman compose -f pkg/net/proxy/softether/testdata/compose.yml run --rm -e LEASE_SECONDS=20 init
echo_ip="$(podman compose -f pkg/net/proxy/softether/testdata/compose.yml exec -T echo hostname -i | awk '{print $1}')"
env SOFTETHER_GATEWAY=127.0.0.1:14443 SOFTETHER_ECHO_IP="$echo_ip" \
  SOFTETHER_TEST_DHCP_RENEWAL=1 \
  go test -tags=softether_interop -run '^TestOfficialSoftEtherDHCPLeaseRenewal$' \
  -count=1 -timeout=60s ./pkg/net/proxy/softether
```

The test waits beyond the original lease expiry and verifies TCP traffic still
passes.
