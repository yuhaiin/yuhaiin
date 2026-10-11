# SSTP outbound

The client carries PPP over the Microsoft SSTP TLS connection and authenticates
with MS-CHAPv2.

```json
{
  "type": "sstp",
  "sstp": {
    "gateway": "vpn.example.com",
    "username": "alice",
    "password": "YOUR_SECRET",
    "insecure_skip_verify": false,
    "mtu": 1400
  }
}
```

`gateway`, `username`, and `password` are required. A gateway may include a
non-default port. `insecure_skip_verify` permits a self-signed TLS certificate;
the PPP handshake still verifies the server's MS-CHAPv2 response. `mtu` is
optional and limits the server-recommended inner MTU.
