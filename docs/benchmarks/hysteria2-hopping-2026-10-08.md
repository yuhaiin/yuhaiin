# Hysteria 2 port hopping benchmark — 2026-10-08

Native target, server and client ran as independent processes across two disposable
rootless Podman containers on a bridge network. Only the server container had
`CAP_NET_ADMIN`. Its wildcard UDP listener used port 4433; native nftables redirected
20000–20020 to it. This exercises external PREROUTING, rather than only loopback
OUTPUT forwarding. The target ran in the client container. Host firewall rules
were unchanged and the runner removed both containers and its network.

AMD Ryzen 5 5600G, `GOMAXPROCS=4`, BBR (both bandwidth settings zero), one TCP
stream, 16 KiB relay buffer. Native/official peers used verified TLS with the same
test CA. Official Hysteria version and Go version are recorded in the raw data.

## TCP

Each primary sample transferred and verified 4 GiB. Fixed and hopping modes were
alternated, three samples per direction/mode. Hopping interval: five seconds.
Every hopping download lasted over eleven seconds (at least two hop periods),
and uploads lasted over twenty-nine seconds. TCP payload integrity passed.

| Mode | Download median | Upload median |
| --- | ---: | ---: |
| Fixed port | 3034 Mbps | 4834 Mbps |
| Hopping | 2939 Mbps | 1174 Mbps |

Download was about 3.1% lower in this local test. Upload showed a substantial CPU
throughput reduction. Additional 1 GiB comparisons isolated its cause:

| Upload comparison | Throughput |
| --- | ---: |
| Native fixed port | 4709 Mbps |
| Native hopping, 5-second interval | 1200 Mbps |
| Native hopping, 3600-second interval (no hop during transfer) | 1198 Mbps |
| Official hopping client → native server | 1131 Mbps |
| Native fixed port, GSO explicitly disabled | 1180 Mbps |
| Native hopping, GSO explicitly disabled | 1202 Mbps |

The upstream `udphop` transport exposes `PacketConn` but does not implement
QUIC's `OOBCapablePacketConn`. QUIC therefore uses `basicConn`, disabling UDP
segmentation offload (GSO) and its other OOB optimizations. The unchanged result
without an actual hop, the official client comparison, and disabling GSO on the
fixed-port path identify the loss of send offload as the main cause here.
The optimized server send path remains available with native nftables forwarding.
There is no additional userspace relay in the server hopping implementation.

This implementation intentionally reuses the upstream hopping transport. Restoring
GSO for hopping would require a transport supporting ancillary messages and
socket rotation correctly, which is outside this change. A multi-gigabit local
CPU ceiling is not a prediction of WAN throughput, loss recovery or ISP throttling;
these results also do not demonstrate a benefit from hopping on a particular WAN.

## UDP and lifecycle

Each UDP workload used one session, 1000-byte payloads, 10,000 packets/s,
120,000 packets over twelve seconds (80 Mbps offered load, two hop periods).
Primary measurements:

| Client mode | Received | Loss | Corruption |
| --- | ---: | ---: | ---: |
| Native fixed | 119967 / 120000 | 0.0275% | 0 |
| Native hopping | 119984 / 120000 | 0.0133% | 0 |
| Official hopping | 120000 / 120000 | 0% | 0 |

These are single UDP samples, not statistical estimates of a loss rate. Diagnostic
reruns varied between 0% and 0.0825% loss at the same offered load. Official client
TCP and UDP forwarding both interoperated with the native server's hop ports.

The integration test independently kept one TCP stream and one UDP session open
through two hops in isolated namespaces. IPv4 and IPv6 with Salamander passed;
proxy-chain socket creation continued after setup cancellation, the TCP stream
was not reopened, the UDP migration ID stayed constant, and all sockets and the
scoped nftables tables were cleaned up. It also checked destination address
scoping, preservation of the reply source port, and startup rollback on invalid
TLS. The same test passed inside Podman with `NET_ADMIN` and no host network.

## Reproduce

The image needs a shell and glibc for the SQLite fixture. For example use an
existing Debian-based image; Podman can pull it if needed.

```sh
python scripts/bench/hysteria2/run_hopping.py \
  --official /absolute/path/to/hysteria-linux-amd64 \
  --image docker.io/library/debian:trixie-slim \
  --output /tmp/hysteria2-hopping.json

# Reduced workload, plus no-hop and official upload/download comparisons:
python scripts/bench/hysteria2/run_hopping.py \
  --official /absolute/path/to/hysteria-linux-amd64 \
  --image docker.io/library/debian:trixie-slim \
  --output /tmp/hysteria2-hopping-diagnostic.json \
  --diagnose --repeats 1 --bytes 1073741824

# Same reduced workload with GSO disabled for both containers:
python scripts/bench/hysteria2/run_hopping.py \
  --official /absolute/path/to/hysteria-linux-amd64 \
  --image docker.io/library/debian:trixie-slim \
  --output /tmp/hysteria2-hopping-no-gso.json \
  --disable-gso --repeats 1 --bytes 1073741824
```

Raw measurements: [primary](data/hysteria2-hopping-2026-10-08.json),
[diagnostic](data/hysteria2-hopping-diagnostic-2026-10-08.json),
[GSO disabled](data/hysteria2-hopping-no-gso-2026-10-08.json).
