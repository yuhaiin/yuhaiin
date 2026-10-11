# Native OpenVPN outbound

Pure Go, no CGO, external OpenVPN client, root privileges, or host TUN. The
native TLS/IP tunnel feeds the same in-process gVisor stack as WireGuard,
GlobalProtect and SoftEther. Both application TCP and UDP use the tunnel.

## Configuration

```json
{
  "id": "ovpn-1",
  "name": "OpenVPN",
  "origin": "manual",
  "enabled": true,
  "chain": [{
    "type": "openvpn",
    "openvpn": {
      "gateway": "vpn.example.com:1194",
      "network": "udp",
      "ca_cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
      "client_cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
      "client_key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
      "username": "alice",
      "password": "YOUR_SECRET",
      "tls_crypt_key": "-----BEGIN OpenVPN Static key V1-----\n...\n-----END OpenVPN Static key V1-----",
      "data_ciphers": ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"],
      "auto_reconnect": true,
      "mtu": 1400
    }
  }]
}
```

- `gateway` requires a port; `network` defaults to `udp`, or use `tcp` for an
  OpenVPN TCP server. Both outer transports honor the preceding proxy in a node
  chain. Unsupported upstream UDP returns an error without a direct fallback.
- Certificate auth, username/password auth, or both are supported. Omit both
  client PEM fields for a server configured with `verify-client-cert none`.
- Certificates are verified against `ca_cert_pem` or system roots, including
  the server-auth EKU. OpenVPN commonly uses CA-issued certificates without
  DNS SANs. Optional `server_name` additionally verifies the DNS/IP identity.
  `insecure_skip_verify` disables these checks only by explicit opt-in.
- `tls_auth_key` and `tls_crypt_key` are mutually exclusive inline static keys.
  For tls-auth, `auth` supports SHA1 (default), SHA256, and SHA512;
  `key_direction` is 0 or 1, or omitted/-1 for bidirectional keys. A usual client
  profile with `tls-auth ta.key 1` requires `key_direction: 1`.
- `data_ciphers` restricts the offered AEAD suites; an unoffered selection is
  rejected. Empty uses the three AEAD suites shown above. Compression,
  CBC/static-key data mode, TAP, tls-crypt-v2, interactive MFA, fragmented
  PUSH_REPLY, and unadvertised TLS-EKM negotiation are explicitly unsupported.
- IPv4 subnet and net30/point-to-point addressing and pushed IPv6 prefixes are
  supported. `mtu` is optional; the server value or 1500 is used otherwise.
  IPv6 requires at least 1280. The configured value can lower the pushed MTU.
- `renegotiate_seconds` defaults to 3600. TLS soft-reset rekey rotates key IDs
  1 through 7, accepting the previous data key for a 60-second transition.
  Established TCP/UDP sockets survive a successful rekey. Server-initiated
  rekey follows the same path.
- `auto_reconnect` opts into full session recreation after transport failure,
  authenticated RESTART or ping-restart timeout. Backoff grows from 1 to 60
  seconds and cancels on close; rejected authentication stops retries. Existing
  application sockets do not migrate across full reconnections.

Pushed DNS and routes are exposed through the node's existing extra-info API;
configure yuhaiin's DNS and routing explicitly. This outbound never applies
host routes, runs profile scripts, or reads paths supplied by a VPN server.
The configuration is a typed JSON node payload, not an `.ovpn` file parser.
Credentials follow the existing node-store/export security model.

## Validation and benchmarks

```sh
go test -race ./pkg/net/proxy/openvpn/... ./pkg/contract/node ./pkg/register
python3 scripts/bench/openvpn/run.py --runtime podman
python3 scripts/bench/openvpn/run.py --runtime podman --benchmark \
  --output /tmp/openvpn-results.json
```

The runner creates ephemeral CA/client/server keys, starts stock OpenVPN in a
container, and removes containers and keys on exit. The **server container**
needs NET_ADMIN and `/dev/net/tun`; the Go client uses neither. Docker also works.
The PR workflow runs the real-server matrix, not just an in-process simulator.
Tests cover TCP/UDP egress with IPv4 and IPv6, CA and password rejection,
keepalive, reconnect and nine rekeys preserving an existing TCP connection.
An additional two-second server renegotiation case verifies server-initiated
rekeys, including key-ID reuse, while keeping the same application connection.

[Measured local results](../../../../docs/benchmarks/openvpn-2026-10-11.md)
include topology and limitations. UDP benchmarks are sequential request/response
latency, not a sustained UDP throughput claim.

## Provenance

The wire codec, control reliability, static-key wrappers, key-method-2 PRF and
initial AES-256-GCM primitive are adapted from
[xen0bit/veepin](https://github.com/xen0bit/veepin/tree/810e017596c0b5b55bc0da563929bde13a6b201d/internal/openvpn)
(MIT); [license](native/THIRD_PARTY_LICENSE). Yuhaiin's integration adds its own
session lifecycle, validation, TCP transport, rekey and gVisor adapter. No new
Go module dependency is introduced. This implementation still needs broader
commercial/enterprise provider testing beyond the documented stock-server matrix.
