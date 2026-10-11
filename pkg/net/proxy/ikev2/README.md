# IKEv2 outbound

The client negotiates IKEv2/IPsec and carries TCP and UDP proxy traffic through
an in-process ESP tunnel.

```json
{
  "type": "ikev2",
  "ikev2": {
    "gateway": "vpn.example.com",
    "local_id": "alice@example.com",
    "server_id": "vpn.example.com",
    "psk": "YOUR_SECRET",
    "username": "alice",
    "password": "YOUR_SECRET",
    "tcp": false,
    "mtu": 1400
  }
}
```

`gateway`, `local_id`, and `psk` are required. `username` and `password` enable
EAP-MSCHAPv2 when the server requires it; the PSK still authenticates the
server. `server_id` optionally pins the expected server identity. UDP/NAT-T is
the default. Set `tcp` only when the gateway supports RFC 8229 TCP
encapsulation. `mtu` optionally lowers the server's recommended tunnel MTU.

The contract-level node currently exposes PSK and EAP authentication. The
lower-level Go client also supports certificate authentication, rekey tuning,
and IP-TFS options.
