# AnyConnect outbound

The client uses the AnyConnect-compatible XML login exchange and CSTP tunnel.
When the gateway offers DTLS, packets use its UDP data channel; otherwise they
remain on TLS/TCP.

```json
{
  "type": "anyconnect",
  "anyconnect": {
    "gateway": "vpn.example.com",
    "username": "alice",
    "password": "YOUR_SECRET",
    "disable_dtls": false,
    "insecure_skip_verify": false,
    "mtu": 1400
  }
}
```

`gateway`, `username`, and `password` are required. A gateway may include a
non-default port. `disable_dtls` forces the TLS data channel. Use
`insecure_skip_verify` only for a server certificate that cannot be validated.
`mtu` is optional and limits the MTU requested from the server.
