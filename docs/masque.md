# Cloudflare WARP MASQUE

Local regression coverage, HTTP/2 framing benchmarks and validation limits: [2026-10-18 review](benchmarks/native-hy2-masque-2026-10-18.md).

MASQUE uses the local CONNECT-IP implementation in `pkg/net/proxy/masque/connectip` on top of `github.com/apernet/quic-go` (HTTP/3).
It no longer imports `github.com/quic-go/quic-go` or `github.com/quic-go/connect-ip-go`.

## Transport

Cloudflare WARP node configuration accepts a `transport` string:

- `"h3"` or omitted: QUIC + HTTP/3 with native BBR (standard profile), preferred/default.
- `"h2"`: TLS/TCP + HTTP/2 extended CONNECT and DATAGRAM capsules, useful where UDP is unavailable. This transport uses the OS TCP congestion controller, **not** QUIC BBR.

The transport is selected explicitly and never silently downgraded. Existing stored nodes work without modifications.

## Compatibility and safety

Cloudflare WARP requires `cf-connect-ip`, legacy HTTP/3 Datagram setting `0x276`, and a 20-byte client QUIC connection ID. The client advertises local IPv4/IPv6 routes and doesn't require Cloudflare to advertise routes to arbitrary public destinations for outgoing IP packets.

The endpoint public key is pinned, and missing/incorrect server certificates are rejected. Invalid IP headers, hop limit exhaustion and oversized datagrams are handled in the CONNECT-IP layer; ICMP Packet Too Big feedback is retained.

The HTTP/2 mode uses an explicitly configured TLS endpoint with ALPN `h2`, and tolerates the empty ALPN response used by some Cloudflare WARP endpoints. This is client-side support only, not a general MASQUE server.

## Development

```sh
go test -race -count=1 ./pkg/net/proxy/masque/...
go test ./pkg/net/proxy/hysteria2/internal/congestion/...
```

The vendor-derived CONNECT-IP files retain their MIT license and the HTTP/2 framing port retains the MPL-2.0 license. Real-service interoperability should be validated with Cloudflare credentials before release.
