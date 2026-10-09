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

## Port hopping

The client accepts the [official list/range syntax](https://v2.hysteria.network/docs/advanced/Port-Hopping/) in `host`, for example
`server.example.com:443,20000-20020` or `[2001:db8::1]:20000-20020`. It changes
both the destination port and local UDP socket while retaining the same QUIC
connection, TCP streams and UDP sessions. This is periodic hopping, not parallel
transmission over multiple paths. Scoped IPv6 addresses are unsupported for hopping.

Client intervals are in seconds:

```json
{ "host": "server.example.com:20000-20020", "hop_interval_seconds": 30 }
```

Alternatively set `min_hop_interval_seconds` and `max_hop_interval_seconds` for a
random interval. Fixed and random settings are mutually exclusive; the minimum
is 5 seconds. All three zero/omitted means 30 seconds. A single port retains the
existing non-hopping transport. DNS, SNI and the preceding chain proxy use the
existing mechanisms; subsequent hop sockets use the client's lifetime context.

On the server, keep a single UDP listen address (for example `0.0.0.0:443`) and
set the protocol's optional `hopPorts` to `20000-20020` or `443,20000-20020`.
On Linux this installs native nftables rules forwarding those UDP ports to the
listener. Rules cover external arrivals and local clients, are scoped to the
bound address (or local destinations for a wildcard listener), and are removed
when the inbound stops. A stable per-listener table replaces stale rules after a
restart on the same bound address. No additional UDP listeners or userspace forwarding process is needed.

Automatic server rules require kernel nftables/NAT support and root or
`CAP_NET_ADMIN` in the listener's network namespace. In Podman, use
`--cap-add NET_ADMIN`; ports must also be published or reachable through its
network. Permit **every hop UDP port** in host firewalls and cloud security
groups. Choose ranges that do not overlap other services or inbounds. An explicit
`hopPorts` setting fails if rules cannot be installed; it does not silently fall
back. On other operating systems, leave `hopPorts` empty and manage UDP
forwarding externally. Empty `hopPorts` also allows existing external forwarding
on Linux. Server bandwidth, TLS-auto and Salamander work unchanged with hopping.

The frontend exposes the port list/range and interval controls. An isolated
Linux integration test keeps TCP and UDP sessions active through two hops over
IPv4 and IPv6/Salamander and checks socket/rule cleanup. For an external-client
container test and throughput comparison, run:

```sh
python scripts/bench/hysteria2/run_hopping.py \
  --official /absolute/path/to/hysteria-linux-amd64 \
  --image docker.io/library/debian:trixie-slim \
  --output /tmp/hysteria2-hopping.json
```

This creates and removes its own Podman network and containers. Only the server
container receives `NET_ADMIN`; host firewall rules are not changed. The image
needs a shell and glibc for the native SQLite fixture.

## Address hopping through UDP relays

To switch between multiple UDP relays to the **same Hysteria 2 server and UDP
listener**, add `hop_addresses` to the client configuration. `host` is included
as the first relay; additional entries accept the same single-port, list and
range syntax as `host`:

```json
{
  "host": "relay-a.example.com:20000-20020",
  "hop_addresses": [
    "relay-b.example.com:30000-30020",
    "[2001:db8::1]:443"
  ],
  "hop_interval_seconds": 30,
  "tls": { "servernames": ["hy2.example.com"] }
}
```

Keep the normal `auth` and CA certificate settings. The TLS server name is
fixed for the entire connection: explicitly set it to the final server's
certificate name when the relay hostname differs. If omitted, it continues to
default to the hostname in `host`.

With `hop_addresses` set, every A/AAAA address returned by the configured
resolver for `host` and each additional hostname enters the hop pool. For
example, `"host": "relays.example.com:443"` together with
`"hop_addresses": ["relays.example.com:443"]` enables hopping across all of
that domain's returned IPs. Each hostname is resolved once per session; DNS is
refreshed when a new session is established, not on every hop or by TTL. The
existing resolver's address-family options are respected. All configured
hostnames must resolve successfully. Entries resolving to the same IP have their
port sets merged. Initially an IP and one of its ports are chosen randomly. On each
hop, a different IP is chosen when available, then one of that IP's ports.
Selection gives each resolved IP equal weight regardless of its port count.
Fixed/random interval settings and defaults are shared with port hopping.
Scoped IPv6 addresses are unsupported.
Omitting or clearing `hop_addresses` retains the existing single-IP selection
for ordinary hostnames and port hopping, even when DNS returns multiple IPs.

The transport opens a new socket for the selected relay, including the correct
address family and preceding chain proxy destination. It temporarily keeps the
previous socket receiving replies. The QUIC connection, TCP streams and UDP
sessions remain the same. The server requires no additional address-hopping
configuration; every relay must forward UDP without terminating QUIC, and NAT
or forwarding must provide a working return path through that relay. Independent
Hysteria servers cannot share an existing connection simply by using the same
password and certificate.

The client transport uses portable Go UDP sockets and explicitly opens `udp4`
or `udp6` for the selected relay. IPv4 and IPv6 entries can therefore share one
hop pool, including on macOS, provided both families are reachable. Linux
nftables support is only needed for the server's optional automatic port-range
rules, not for client-side address hopping. macOS amd64/arm64 builds are checked;
mixed-family runtime tests currently run on Linux, not on a real Mac.

This is periodic switching, not health-based failover or simultaneous multipath.
A local socket-open failure skips that hop. An unreachable relay is not detected
before switching: traffic may stall until the next hop, and an extended outage
can exceed QUIC's idle timeout and close existing sessions. Relays with different
latency, bandwidth or MTU can cause pauses or retransmissions during a switch.
Like the existing port-hopping transport, this uses QUIC's generic PacketConn
path without client GSO/OOB optimizations. WAN throughput has not been benchmarked.

`TestAddressHoppingKeepsTCPAndUDPSessions` exercises two timed hops through
distinct relay IPs with persistent TCP/UDP sessions, direct and preceding-proxy
transports, Salamander, mixed IPv4/IPv6 relay addresses, and socket cleanup.
These userspace UDP relays require no root privileges or firewall changes.

## Bandwidth and obfuscation

All bandwidth values use **bytes per second**, from each endpoint's perspective. `uploadBps` / `upload_bps` configure bytes sent; `downloadBps` / `download_bps` configure bytes received. Thus server upload is client download. Zero uses upstream automatic congestion control (BBR); positive bandwidth follows upstream negotiation and Brutal. Nonzero values must be at least 65536. For example, 200 Mbps is 25000000 bytes/second. Server `ignoreClientBandwidth` requests automatic congestion control instead of honoring the client's bandwidth declaration.

Set server `salamanderPassword` and client `salamander_password` to the same separate password to enable Salamander. The password must contain at least four bytes. Leaving the field empty disables obfuscation. Mixed configurations do not interoperate.

The server supplies the real peer/local addresses to the existing stream handler and a unique NAT migration ID for every UDP session. Destination changes within a UDP session are preserved. The embedding handler owns sniffing, routing, DNS hijacking, accounting and relay. TCP requests are accepted before that handler dials the destination; a subsequent target dial failure closes the stream. Unauthenticated HTTP/3 requests receive upstream's default 404 response.

Gecko, configurable webpage/reverse-proxy masquerade and share URL import/export are deferred. Related source comments identify those boundaries.

## Frontend configuration

[Companion frontend PR #453](https://github.com/yuhaiin/yuhaiin-react/pull/453) adds structured Hysteria 2 node and inbound editors. In the inbound Protocol section, select `hysteria2` and choose **Use**. The editor keeps the listen address, selects UDP-only and retains one existing TLS certificate configuration, or supplies `tls_auto` by default. Enter the shared password and the Server Names that clients will use as SNI, then save. Copy the generated public CA Cert into the client node's CA Certificate list; keep verification enabled and configure the same SNI.

The client and server editors expose bandwidth in bytes/s and optional Salamander passwords. Server controls also include ignoring client bandwidth and disabling UDP proxying. TLS-auto CA/auth fields survive saves and reselection. Hysteria manages ALPN, so its editors hide the TLS-enable and ALPN controls.

Merge the frontend companion before releasing the backend. Its existing workflow publishes the frontend bundle to `yuhaiin/yuhaiin.github.io`; the Go build workflow resolves and embeds that published revision. For local validation, run the backend with `-eweb /absolute/path/to/yuhaiin-react/dist` after building the frontend. The two PRs were tested together this way against a real SQLite store and TCP/UDP forwarding.

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

Port hopping results, including the upstream client GSO limitation, are recorded
in the [2026-10-08 hopping report](benchmarks/hysteria2-hopping-2026-10-08.md).
