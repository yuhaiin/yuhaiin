# Fortinet SSL VPN outbound

The client logs in to FortiOS over HTTPS, reads the assigned tunnel settings,
and carries PPP over TLS. If the gateway offers the DTLS data channel, the
client uses it unless `disable_dtls` is set.

```json
{
  "type": "fortinet",
  "fortinet": {
    "gateway": "vpn.example.com",
    "username": "alice",
    "password": "YOUR_SECRET",
    "realm": "",
    "ca_cert_pem": "",
    "insecure_skip_verify": false,
    "disable_dtls": false,
    "mtu": 1400
  }
}
```

`gateway` and `username` are required. `token` supplies one second-factor
code; `totp_secret` lets the client generate codes for later logins. Use
`ca_cert_pem` for a private CA, or explicitly set `insecure_skip_verify` when
the gateway certificate cannot be validated. `mtu` is optional and limits the
recommended inner MTU.
