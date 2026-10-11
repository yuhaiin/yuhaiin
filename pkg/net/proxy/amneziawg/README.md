# AmneziaWG outbound

AmneziaWG v3 uses the official `amneziawg-go` userspace engine and yuhaiin's
existing in-process IP stack. No host TUN device or route changes are needed.

```json
{
  "type": "amneziawg",
  "amneziawg": {
    "secretKey": "BASE64_PRIVATE_KEY",
    "endpoint": ["10.8.0.2/32"],
    "peers": [{
      "publicKey": "BASE64_PEER_PUBLIC_KEY",
      "endpoint": "vpn.example.com:51820",
      "allowedIps": ["0.0.0.0/0", "::/0"],
      "keepAlive": 25
    }],
    "jc": 4,
    "jmin": 40,
    "jmax": 70,
    "s1": 0,
    "s2": 0,
    "h1": "123456789",
    "h2": "987654321",
    "h3": "192837465",
    "h4": "564738291"
  }
}
```

`endpoint` is the local tunnel address list. Peer keys use standard Base64
encoding. `jc`, `jmin`, `jmax`, `s1`–`s4`, `h1`–`h4`, `i1`–`i5`,
`header_protection_key`, `content_padding_addition`, `random_trailers`, and
`disable_cookies` configure the Amnezia obfuscation layer. These values must
match the server peer configuration. `mtu` is optional and defaults to 1400.

Peer options are `publicKey`, `preSharedKey`, `endpoint`, `keepAlive`, and
`allowedIps`, matching the WireGuard peer shape.
