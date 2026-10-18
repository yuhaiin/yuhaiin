# Cloudflare WARP MASQUE

Local regression coverage, HTTP/2 framing benchmarks and validation limits: [2026-10-18 review](benchmarks/native-hy2-masque-2026-10-18.md).

MASQUE uses the local CONNECT-IP implementation in `pkg/net/proxy/masque/connectip` on top of `github.com/apernet/quic-go` (HTTP/3).
It no longer imports `github.com/quic-go/quic-go` or `github.com/quic-go/connect-ip-go`.

## Transport

Cloudflare WARP node configuration accepts a `transport` string:

- `"h3"` or omitted: QUIC + HTTP/3 with native BBR (standard profile), preferred/default.
- `"h2"`: TLS/TCP + ordinary HTTP/2 CONNECT with `cf-connect-proto: cf-connect-ip` and DATAGRAM capsules, useful where UDP is unavailable. This transport uses the OS TCP congestion controller, **not** QUIC BBR.

The transport is selected explicitly and never silently downgraded. Existing stored nodes work without modifications.

## Compatibility and safety

Cloudflare WARP uses `cf-connect-ip`, legacy HTTP/3 Datagram setting `0x276`, and a 20-byte client QUIC connection ID. H3 sessions install the shared BBR **standard** controller and enable automatic path MTU discovery. The H3 client advertises local IPv4/IPv6 routes and doesn't require Cloudflare to advertise routes to arbitrary public destinations for outgoing IP packets.

Cloudflare H2 carries raw IPv4/IPv6 packets inside type-0 DATAGRAM capsules without an IP context ID. The local IPv4/IPv6 receive policy is configured without sending ROUTE_ADVERTISEMENT or address-management capsules. Other incoming capsule types are skipped, matching usque's H2 adapter. This mode requires neither the RFC 8441 `:protocol` pseudo-header nor the server's extended-CONNECT setting.

The endpoint public key is pinned, and missing/incorrect server certificates are rejected. Invalid IP headers, hop limit exhaustion and oversized datagrams are handled in the CONNECT-IP layer; ICMP Packet Too Big feedback is retained.

The HTTP/2 mode uses an explicitly configured TLS endpoint with ALPN `h2`, and tolerates the empty ALPN response used by some Cloudflare WARP endpoints. This is client-side support only, not a general MASQUE server.

Configure the H2 TCP endpoint and its public-key pin explicitly. H2 and H3 endpoints can differ, as can their TLS public keys; create separate nodes when retaining both transports. The pin remains mandatory.

## usque compatibility reference

Reviewed against [usque `6aa03fc9`](https://github.com/Diniboy1123/usque/tree/6aa03fc97d12848dce34eedbd187fb1077b5d1ea), its pinned [connect-ip-go `66cba32d`](https://github.com/Diniboy1123/connect-ip-go/tree/66cba32d7d33), and its [HTTP/2 notes](https://github.com/Diniboy1123/usque/wiki/HTTP-2-support). MIT attribution is retained in `USQUE_MIT_LICENSE` alongside the existing CONNECT-IP and HTTP/2 licenses.

The usque comparison added the datagram-only H2 behavior and restored default QUIC PMTU discovery. The outer UDP socket selects the endpoint's IPv4/IPv6 family and uses its routing hint through the project socket-protection dialer. Real loopback H3 connections over IPv4 and IPv6 through the default BBR setup now discover sufficient MTU and echo a 1280-byte IPv6 packet; a TCP/H2 peer checks ordinary CONNECT, Cloudflare headers, no setup control capsules, and raw IPv4/IPv6 framing without advertising extended CONNECT.

The send queue reserves 16 bytes of packet headroom, allowing CONNECT-IP to prepend its context/capsule header without an extra payload copy/allocation. Bounds, IPv4 options/checksum, IPv6 hop limit and the insufficient-headroom fallback are covered by regressions. QUIC and HTTP/2 still perform their own transport copies; this is not an end-to-end zero-copy claim.

Apple M4 / Go 1.27.2, `-cpu=1 -count=5 -benchtime=500ms`: a 1200-byte encoding fixture measured median **133.0 ns, 1280 B and 1 allocation** with the copying API versus **23.73 ns, 0 B and 0 allocations** with headroom. This excludes encryption, sockets and live Cloudflare endpoints. [Raw samples](benchmarks/data/native-hy2-masque-2026-10-18/masque-headroom-after.txt).

## Development

The node page's UDP Ping uses DNS-over-QUIC (DoQ), rather than plain DNS/UDP.
DoQ starts with a 1200-byte QUIC UDP payload so the Initial and IPv6/UDP headers
fit a 1280-byte tunnel without fragmentation; QUIC PMTU discovery remains enabled.
The local transmit MTU does not cap received peer IP packets. MASQUE accepts a
complete validated packet and pools storage for its actual size, so a peer's
1280-byte QUIC UDP payload (1308-byte IPv4 or 1328-byte IPv6 packet) cannot cause
a short-buffer error and reconnect the entire tunnel.

This was reproduced on a remote Linux host with live Cloudflare WARP credentials:
plain UDP DNS and STUN succeeded while the page's DoQ timed out. Both IPv4 and
IPv6 DoQ succeeded after the fixes with the original MTU 1280 retained. The
regressions exercise the real DoQ dial and a complete H3/IP/UDP tunnel, including
another UDP exchange after the large reply. Credentials are not stored in the
tests or this repository.

```sh
go test -race -count=1 ./pkg/net/proxy/masque/...
go test -race -count=1 ./pkg/net/dns/resolver
go test ./pkg/net/proxy/hysteria2/internal/congestion/...
```

The vendor-derived CONNECT-IP files retain their MIT license and the HTTP/2 framing port retains the MPL-2.0 license. Real-service interoperability should be validated with Cloudflare credentials before release.
