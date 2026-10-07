# Hysteria 2

The Go backend supports Hysteria 2 TCP and UDP clients/servers, authenticated with one nonempty shared `auth` string. It uses the upstream core and Salamander implementation; the QUIC module `github.com/apernet/quic-go` coexists with the original QUIC module used by other protocols.

## Server configuration

Save this inbound through the existing `inbound.put` RPC. Hysteria owns QUIC and HTTP/3, so select the existing `tcp_udp` network in `udp_only` mode. Its `tls` or `tls_auto` transport configures the QUIC handshake rather than wrapping a TCP listener.

```json
{
  "id": "hy2-server",
  "name": "Hysteria 2",
  "enabled": true,
  "network": {
    "type": "tcp_udp",
    "tcp_udp": { "host": "0.0.0.0:443", "udp": "udp_only" }
  },
  "transports": [
    {
      "type": "tls_auto",
      "tls_auto": { "serverNames": ["hy2.example.com"] }
    }
  ],
  "protocol": {
    "type": "hysteria2",
    "hysteria2": {
      "auth": "replace-with-your-password",
      "uploadBps": 0,
      "downloadBps": 0,
      "ignoreClientBandwidth": false,
      "disableUdp": false
    }
  }
}
```

`tls_auto` creates and persists a private CA in the existing inbound store. Obtain its public `caCertBase64` through `inbound.get` and decode it to a CA PEM file for clients. Treat `caKeyBase64` as private key material. Restarting the server keeps its CA; leaf certificates are regenerated as needed. Configure a matching, nonempty SNI. Hysteria uses ECDSA leaf keys even with an existing Ed25519 CA, to support the upstream Chrome handshake fingerprint.

A static `tls` transport with the existing `certificates` / `serverNameCertificate` fields is also supported. Other TCP transports and the existing custom `quic` network cannot wrap Hysteria.

## Client configuration

Save a node through `node.put` (or `nodes.post`), using the usual tagged chain representation:

```json
{
  "id": "hy2-client",
  "name": "Hysteria 2",
  "group": "default",
  "origin": "manual",
  "enabled": true,
  "chain": [
    {
      "type": "hysteria2",
      "hysteria2": {
        "host": "server.example.com:443",
        "auth": "replace-with-your-password",
        "tls": {
          "servernames": ["hy2.example.com"],
          "ca_cert": ["BASE64_OF_CA_PEM"],
          "insecure_skip_verify": false
        },
        "upload_bps": 0,
        "download_bps": 0
      }
    }
  ]
}
```

`ca_cert` is a list of base64-encoded PEM blobs, following the existing Go TLS contract. With a publicly trusted server certificate, omit it. Certificate verification is enabled by default. `insecure_skip_verify` remains an explicit option. TLS is mandatory regardless of the optional `tls.enable` value; ALPN is managed by Hysteria. The endpoint defaults to port 443; absent explicit SNI, its hostname is used.

The client obtains its UDP transport from the preceding chain proxy. It opens one shared QUIC connection lazily, respects caller cancellation during setup, and reconnects for new requests after disconnection. Existing streams/UDP sessions fail on disconnection and are not replayed. Closing a client permanently closes it.

## Bandwidth and obfuscation

All bandwidth values use **bytes per second**, from each endpoint's perspective. `uploadBps` / `upload_bps` configure bytes sent; `downloadBps` / `download_bps` configure bytes received. Thus server upload is client download. Zero uses upstream automatic congestion control (BBR); positive bandwidth follows upstream negotiation and Brutal. Nonzero values must be at least 65536. For example, 200 Mbps is 25000000 bytes/second. Server `ignoreClientBandwidth` requests automatic congestion control instead of honoring the client's bandwidth declaration.

Set server `salamanderPassword` and client `salamander_password` to the same separate password to enable Salamander. The password must contain at least four bytes. Leaving the field empty disables obfuscation. Mixed configurations do not interoperate.

The server supplies the real peer/local addresses to the existing stream handler and a unique NAT migration ID for every UDP session. Destination changes within a UDP session are preserved. The embedding handler owns sniffing, routing, DNS hijacking, accounting and relay. TCP requests are accepted before that handler dials the destination; a subsequent target dial failure closes the stream. Unauthenticated HTTP/3 requests receive upstream's default 404 response.

Gecko, port hopping, configurable webpage/reverse-proxy masquerade, share URL import/export and React configuration controls are deferred. Related source comments identify those boundaries.

## Fork maintenance and validation

The minimal fork is [Asutorufa/hysteria, codex/yuhaiin-inbound](https://github.com/Asutorufa/hysteria/tree/codex/yuhaiin-inbound). Its [maintenance notes](https://github.com/Asutorufa/hysteria/blob/codex/yuhaiin-inbound/YUHAIIN.md) describe the additive request callbacks, context-aware client setup, shutdown ownership and oversized UDP fix. The dependency is pinned to a commit in `go.mod`, not a moving branch.

Merge upstream into the fork, run its core tests, then run these checks before updating the pinned revision:

```sh
go test -race ./pkg/net/proxy/hysteria2 ./pkg/inbound ./pkg/cert ./pkg/net/proxy/tls
python scripts/bench/hysteria2/run.py \
  --official /absolute/path/to/hysteria-linux-amd64 \
  --output /tmp/hysteria2-benchmark.json
```

The benchmark uses independent target, server and client processes, IPv4 loopback and `GOMAXPROCS=4`. It exercises the real native inbound handler/NAT with direct outbound. It checks native/official pairings, TLS-auto CA persistence, BBR, configured 200 Mbps Brutal and Salamander. TCP measurements verify payloads or acknowledge received byte counts; UDP measurements record offered/received throughput, packet loss and corruption. It preserves raw results and medians over three repetitions. It measures local CPU/adapter overhead and does not establish WAN or lossy-path throughput.

Measured results and the existing relay buffer tuning are recorded in the [2026-10-07 benchmark report](benchmarks/hysteria2-2026-10-07.md).
