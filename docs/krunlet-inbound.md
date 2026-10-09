# Krunlet inbound (local microVM network)

The `krunlet` inbound connects a local
[Krunlet](https://github.com/Asutorufa/krunlet) microVM to yuhaiin's
normal traffic-routing pipeline. It is **not** a SOCKS5/HTTP proxy:
Krunlet decodes guest virtio-net packets with gVisor and sends each
TCP stream or UDP flow to yuhaiin over a local Unix-domain socket.
The yuhaiin inbound submits streams and packets to the same
`netapi.Handler` used by its existing inbounds.

## Example inbound contract

```json
{
  "id": "krunlet-agent-1",
  "name": "Krunlet Agent 1",
  "enabled": true,
  "network": {"type": "empty", "empty": {}},
  "transports": [],
  "protocol": {
    "type": "krunlet",
    "krunlet": {"socket": "/tmp/yuhaiin-krunlet.sock"}
  }
}
```

Save the contract using yuhaiin's normal inbound management API or UI.
Configure the guest to use **the exact same socket**:

```sh
krunlet run --rootfs ./rootfs --network \
  --yuhaiin-socket /tmp/yuhaiin-krunlet.sock \
  -- /bin/sh -c 'echo hello'
```

For Go applications, use `Options{Network: true, Yuhaiin:
&krunlet.YuhaiinConfig{Socket: "/tmp/yuhaiin-krunlet.sock"}}`.

Krunlet can optionally apply its own `NetworkPolicy` before handing
connections to yuhaiin; if omitted, **yuhaiin owns routing and
blocking**. Unlike an outbound proxy configured via SOCKS5, this is
a first-class inbound with its own inbound name and normal yuhaiin
pipeline. DNS queries directed to the guest's IPv4 gateway
`192.168.127.1:53` are passed into the inbound; yuhaiin's normal
DNS hijacking setting must be enabled. DNS/FakeIP handling and stream
sniffing determine how much domain information is available for
routing. IP-only flows do not inherently carry hostnames.

## Wire protocol

`KRN1` per local Unix connection:

- Four ASCII bytes `KRN1`, then protocol byte (`1`=TCP,
  `2`=UDP), then address family byte (`4` or `6`)
- Source port, destination port as two-byte big-endian integers
- Source IP, destination IP, each 4 or 16 bytes depending on family
- TCP: unframed bidirectional byte stream
- UDP: repeated `uint16-be length + payload` datagrams, both ways

No external TCP socket is opened by the inbound. The on-disk Unix
socket is created with mode `0600`; place it in a private
administrator-managed directory when stronger local access isolation
is required. If yuhaiin is unavailable, Krunlet **never silently
falls back** to direct host TCP/UDP.

## Limitations

- Both programs must use the same version of this local wire format.
- Currently forwards reconstructed TCP/UDP traffic, not arbitrary
  ICMP or full raw-IP packets. ICMP/NDP used for guest link
  configuration remains within Krunlet's gVisor gateway.
- Inbound HTTP/TLS transports and TCP/QUIC listeners are intentionally
  not used: configure the `empty` network and no additional transports.
- Rule separation between different microVMs requires distinct inbound
  sockets/IDs. The Unix protocol currently does not authenticate a VM
  identity beyond the local socket's OS permissions.
- The microVM filesystem, host, and network security assumptions still
  require separate end-to-end tests on libkrun `NET=1` builds.
