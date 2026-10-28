# SSTP inbound (rootless)

The SSTP inbound accepts standard SSTP clients over TLS/TCP with PPP,
MS-CHAPv2, IPv4 IPCP and SSTP SHA-256 crypto binding. Each authenticated
session gets a separate in-memory Lightweight TCP/IP stack. It does not create
a host TUN/TAP interface, install routes, or require CAP_NET_ADMIN.

Example inbound contract (use a real certificate and change all credentials):

```json
{
  "id": "sstp",
  "name": "SSTP VPN",
  "enabled": true,
  "network": {"type": "tcp_udp", "tcp_udp": {"host": "127.0.0.1:8443", "udp": "tcp_only"}},
  "transports": [],
  "protocol": {
    "type": "sstp",
    "sstp": {
      "tls": {
        "certificates": [{"certFile": "/etc/yuhaiin/sstp.crt", "keyFile": "/etc/yuhaiin/sstp.key"}]
      },
      "serverAddress": "10.90.0.1",
      "clientAddresses": ["10.90.0.2", "10.90.0.3"],
      "dns": "1.1.1.1",
      "mtu": 1400,
      "maxSessions": 2,
      "users": [{"username": "alice", "password": "REPLACE_ME"}]
    }
  }
}
```

Place an external TCP/TLS passthrough proxy in front of the high port if you
need to share port 443. SSTP crypto binding requires the backend to terminate
TLS itself, so **do not terminate TLS at the reverse proxy**.

All clients must use IPv4; the address pool contains individual client IPs,
not CIDRs. IP source validation prevents clients from sending traffic under
another address. Sessions are bounded by the address pool and maxSessions.
Forwarding uses the existing inbound handler and routing rules, not host NAT.

MS-CHAPv2 is legacy authentication: it requires a plaintext credential or NT
hash equivalent. Ordinary salted login password hashes do not work. SSTP
credentials are therefore configured separately from HTTP/API user accounts.
Protect stored settings, restrict who can administer the inbound, and use a
valid server certificate. RADIUS, EAP, PAP, IPv6 and Ethernet bridging are not
implemented. Interoperability with Windows RRAS and other SSTP clients still
needs independent real-peer verification.
