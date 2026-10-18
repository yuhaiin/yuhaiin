# WireGuard inbound (no system TUN)

This inbound terminates standard WireGuard sessions using `wireguard-go` and
hands decrypted IPv4/IPv6 packets to yuhaiin's in-memory **lightweight TCP/IP**
stack. Streams and datagrams enter the same DNS / routing / proxy handlers as
the existing lightweight TUN inbound. The server never creates a system TUN,
changes host routes, requires CAP_NET_ADMIN or enables kernel IP forwarding.
A normal unprivileged UDP port such as 51820 is sufficient.

## Server configuration

Create an inbound with the following protocol. The server's private key and
each client's public key are base64-encoded 32-byte WireGuard keys. Do not reuse
private keys between installations.

```json
{
  "id": "wg-server",
  "name": "WireGuard Server",
  "enabled": true,
  "network": { "type": "empty", "empty": {} },
  "transports": [],
  "protocol": {
    "type": "wireguard",
    "wireguard": {
      "listenPort": 51820,
      "privateKey": "<SERVER_PRIVATE_KEY_BASE64>",
      "addresses": ["10.66.0.1/24", "fd66::1/64"],
      "mtu": 1420,
      "peers": [{
        "publicKey": "<CLIENT_PUBLIC_KEY_BASE64>",
        "allowedIps": ["10.66.0.2/32", "fd66::2/128"]
      }]
    }
  }
}
```

Use `wg genkey | tee server.key | wg pubkey` to generate a key pair. Configure
one unique host address (/32 or /128) per client in the **server** peer
`allowedIps`. The server rejects broad, overlapping, out-of-subnet or gateway
addresses. A peer PSK is optional and must match on both ends. WireGuard's
cryptokey routing also enforces source addresses after decryption.

## Client example

```ini
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY_BASE64>
Address = 10.66.0.2/32
DNS = 10.66.0.1
MTU = 1420

[Peer]
PublicKey = <SERVER_PUBLIC_KEY_BASE64>
Endpoint = server.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

For IPv6, add `fd66::2/128` to the interface addresses and `::/0` to
client AllowedIPs. The **client** uses default routes for full tunnelling;
the **server** uses only per-client host prefixes. The server bind listens on
wildcard UDP interfaces for the configured port; restrict exposure through the
host firewall if needed.

## Limits and behaviour

- TCP and UDP are accepted as proxy flows. This is **not** a generic L3 router:
  arbitrary IP protocols, peer-to-peer forwarding and non-local ICMP Echo
  forwarding are not supported by the default lightweight configuration.
- An ICMP Echo reply produced locally by the stack is not a measurement of
  latency to a remote destination.
- The lightweight stack is experimental. The server runs the RemoteTunnel
  profile (BBR v3 by default) with a single userspace packet link.
- Key changes or peer edits replace the inbound listener. Exported client
  configurations, port forwarding and peer statistics are not yet automated.
- Ensure IPv6 support and an IPv6-capable MTU (at least 1280) when configuring
  IPv6 addresses. There is no kernel NAT or automatic firewall modification.
