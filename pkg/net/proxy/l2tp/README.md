# L2TP outbound

The `l2tp` node runs L2TPv2 and PPP over the previous proxy's UDP transport.
PPP supports PAP, CHAP-MD5 and MS-CHAPv2, IPCP addresses/DNS and optional
IPv6CP. The `l2tpv3` node carries Ethernet over UDP with a userspace network
stack, ARP and IPv6 neighbor discovery. Neither mode needs a host TUN device.

## Configuration

```json
{"type":"l2tp","l2tp":{
  "gateway":"vpn.example.com:1701",
  "username":"alice","password":"secret",
  "auth_type":"auto","mtu":1400,"auto_reconnect":true
}}
```

`auth_type` accepts `auto` (server negotiation), `pap`, `chap-md5` and
`mschap-v2`. `shared_secret` optionally authenticates the L2TP control tunnel.
`hostname` defaults to `yuhaiin`. Set `ipv6:true` to negotiate IPv6CP;
IPv6CP provides interface identifiers/link-local addresses, so routed IPv6
also needs a server-configured `ipv6_address`, such as `fd88::2/64`.
MTU is 576–1500, defaults to 1400 and must be at least 1280 for IPv6.

```json
{"type":"l2tpv3","l2tpv3":{
  "gateway":"vpn.example.com:1701","remote_end_id":"site-b",
  "shared_secret":"control-secret","sublayer":true,
  "address":"10.89.0.2/24","router":"10.89.0.1",
  "ipv6_address":"fd89::2/64","ipv6_router":"fd89::1","mtu":1400
}}
```

Dynamic L2TPv3 negotiates Ethernet pseudowire session IDs, cookies and the
L2-specific sublayer. The optional shared secret enables RFC 3931 control
message integrity with nonces. Static mode (`static:true`) skips control
negotiation and requires nonzero `local_session_id` and `peer_session_id`.
At least one IPv4/IPv6 address prefix is required; routers are optional.
An optional `local_address` (IP:UDP-port) requests a fixed local UDP bind;
creation fails if the upstream cannot honor a nonzero port.

Static cookies are empty, 4 or 8 bytes, encoded as 8 or 16 hex digits.
`local_cookie` is checked on incoming frames; `peer_cookie` is transmitted.
Linux `ip l2tp` names these from the transmit perspective: client
`local_cookie` matches server `cookie`, and client `peer_cookie` matches
server `peer_cookie`. Both static peers must agree on `sublayer` (`true`
for Linux `l2spec_type default`, `false` for `none`), session IDs and UDP
endpoints. This implementation uses UDP encapsulation, not raw IP protocol 115.

Native L2TP does not encrypt the data channel and does not implement IPsec,
MPPE, PPP compression or Ethernet VLAN trunking. Control authentication and
cookies do not provide data encryption. Use a trusted network or a protected
upstream transport when encryption is needed.

The upstream UDP proxy is always honored. Reconnect uses bounded backoff and
stops after explicit authentication rejection; existing sockets belong to the
old session. `node.extra` reports cached active `l2tp`/`l2tpv3` addresses,
DNS, authentication, MTU and tunnel/session IDs without opening a connection.

## Validation and benchmarks

```sh
go test -race ./pkg/net/proxy/l2tp/... ./pkg/contract/node ./pkg/register
python3 scripts/bench/l2tp/run.py --runtime podman --benchmark --output /tmp/l2tp.json
# Stock xl2tpd/pppd adds CHAP-MD5 and IPv6CP; needs usable /dev/ppp:
python3 scripts/bench/l2tp/run.py --runtime docker --ppp
```

The runner creates isolated containers, builds the client test binary once,
and removes its containers even after test failure. SoftEther exercises raw
L2TP with PAP and MS-CHAPv2, incorrect passwords and reconnect. Linux tests
IPv4/IPv6 TCP and UDP with static and dynamic Ethernet sessions, 4/8-byte
cookies, wrong receive cookies, sublayers and authenticated dynamic control.
Dynamic signalling uses an independent Python RFC 3931 fixture; the Linux
kernel handles its Ethernet data channel. The optional stock xl2tpd/pppd
matrix tests all three PPP authentication types and IPv6CP. CI uses Docker
with PPP/L2TP kernel modules loaded.

Benchmarks run in a separate uninstrumented client process against the
container echo server. TCP uses 256 KiB round trips, UDP uses 1200-byte round
trips, with three 2-second samples. Race-enabled interop runs separately.
These measurements include localhost/container transport and the userspace
network stack; they are not remote encrypted VPN throughput measurements.
