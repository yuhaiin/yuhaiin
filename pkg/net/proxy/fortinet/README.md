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

## FortiOS interoperability test

The interop test uses a real FortiGate or FortiGate-VM SSL VPN tunnel-mode
gateway and an IPv4 UDP echo service reachable through its VPN policy. SSL VPN
tunnel mode was removed starting in FortiOS 7.6.3, so use a FortiOS release that
still supports it, such as 7.4.x or 7.6.2. See the [FortiOS release
notes](https://docs.fortinet.com/document/fortigate/7.6.7/fortios-release-notes/173430/ssl-vpn-tunnel-mode-replaced-with-ipsec-vpn).

Set `FORTINET_TEST_GATEWAY`, `FORTINET_TEST_USERNAME`,
`FORTINET_TEST_PASSWORD`, `FORTINET_TEST_ECHO_IP`, and
`FORTINET_TEST_ECHO_UDP_PORT`, then run:

```sh
go test -race -tags=fortinet_interop -v ./pkg/net/proxy/fortinet
```

Optional settings are `FORTINET_TEST_REALM`, `FORTINET_TEST_TOKEN`,
`FORTINET_TEST_TOTP_SECRET`, `FORTINET_TEST_CA_CERT` (path to a PEM CA bundle),
`FORTINET_TEST_INSECURE=true`, and `FORTINET_TEST_DISABLE_DTLS=true`. Prefer a
trusted CA bundle over disabling certificate verification. Keep test
credentials in the environment or a secret store, never in the repository.
