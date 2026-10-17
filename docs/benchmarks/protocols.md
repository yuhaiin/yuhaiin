# Protocol benchmark snapshots

This page consolidates the last retained Hysteria 2 and OpenVPN benchmark write-ups. **These are dated snapshots, not newly rerun tests or a claim that later code is unchanged.** Each protocol uses a different topology and workload; their numbers must not be ranked against one another.

## Hysteria 2: official interoperability and buffers (2026-10-07)

AMD Ryzen 5 5600G, Linux amd64; independent target/server/client processes on IPv4 loopback, `GOMAXPROCS=4` each, 128 MiB verified TCP workload and three samples per scenario. Native client/server interoperated with official Hysteria 2.13.0, including TLS-auto CA persistence, Salamander obfuscation and configured 200 Mbps Brutal. Compiler and adapter differences limit attribution.

Client-perspective payload throughput, **Mbps**, default BBR with 16 KiB relay buffers:

| Server / client | 1 stream upload | 1 stream download | 4 streams upload | 4 streams download |
| --- | ---: | ---: | ---: | ---: |
| Native / native | 4939.0 | 3062.2 | 4835.5 | 5075.0 |
| Native / official | 3935.1 | 2865.5 | 4449.1 | 4207.6 |
| Official / native | 4938.6 | 4169.0 | 4716.4 | 5190.5 |
| Official / official | 4002.8 | 3984.3 | 4578.3 | 4500.0 |

For the same one-stream native client and native server, an existing **32 KiB relay buffer configuration** (`advanced.relayBufferSize: 32768`) raised measured download from 3062.2 to 4268.7 Mbps. This was a controlled buffer experiment, **not a default-setting change**. In the 160 Mbps offered UDP echo matrix (40,000 × 1000 B packets per case; three repetitions), all 960,000 packets across eight pairings returned intact; this measures that offered load, not maximum UDP capacity.

```sh
python3 scripts/bench/hysteria2/run.py \
  --official /absolute/path/to/hysteria-linux-amd64 \
  --output /tmp/hysteria2-default.json
python3 scripts/bench/hysteria2/run.py \
  --official /absolute/path/to/hysteria-linux-amd64 \
  --scenario bbr --relay-buffer-size 32768 --udp-packets 4000 \
  --output /tmp/hysteria2-buffer32.json
```

## Hysteria 2: port hopping (2026-10-08)

A separate test used two rootless Podman containers on a bridge network, real nftables PREROUTING over UDP ports 20000–20020, verified 4 GiB TCP payloads, 5-second hop interval and three samples per mode. Both peers used BBR with a 16 KiB relay buffer.

| Mode | Download median Mbps | Upload median Mbps |
| --- | ---: | ---: |
| Fixed port | 3034 | 4834 |
| Port hopping | 2939 | 1174 |

The upload deficit was **not** clearly caused by the periodic address switch: 3600-second interval (no hop during transfer) measured 1198 Mbps, and disabling GSO brought the fixed-port comparison to 1180 Mbps versus 1202 Mbps with hopping. This points to an offload-path difference in that environment, not a universal port-hopping ceiling.

```sh
python3 scripts/bench/hysteria2/run_hopping.py \
  --official /absolute/path/to/hysteria-linux-amd64 \
  --image docker.io/library/debian:trixie-slim \
  --output /tmp/hysteria2-hopping.json
```

## OpenVPN: real-server interoperability (2026-10-11)

Stock OpenVPN 2.6.20 in Alpine 3.22 / rootless Podman, with a native Go client using the then-current in-process gVisor path. The host/guest encrypted tunnel reaches independent TCP/UDP echo workers. TCP transfers 16 MiB per iteration with bidirectional echo; the table counts bytes **in one direction**. UDP sends one 1200-byte datagram and waits for its echo, so the µs column is **round-trip latency**, not UDP throughput. Three samples per case, two-second TCP benchmarks.

| Outer | Protection | Cipher | TCP median MB/s | UDP RTT µs |
| --- | --- | --- | ---: | ---: |
| UDP | tls-crypt | AES-256-GCM | 33.39 | 106.5 |
| TCP | tls-crypt | AES-128-GCM | 58.35 | 117.0 |
| UDP | tls-auth | CHACHA20-POLY1305 | 36.60 | 108.4 |
| UDP | none | AES-256-GCM | 35.95 | 106.5 |

The dated correctness run covered IPv4/IPv6 TCP and UDP egress, rejected certificates/passwords, keepalive, reconnection and manual/server-initiated rekey without breaking the established TCP flow. **This is not a measurement of the later lightweight VPN adapter**: see [the current integration documentation](../lightweight-tcpip-stack.md#vpn-tunnel-integration).

```sh
python3 scripts/bench/openvpn/run.py \
  --runtime podman --benchmark --output /tmp/openvpn-results.json
```

For raw protocol samples/diagnostics from those dates, use Git history at the respective original paths: `docs/benchmarks/hysteria2-2026-10-07.json`, `docs/benchmarks/data/hysteria2-hopping-2026-10-08.json` and `docs/benchmarks/data/openvpn-2026-10-11.json`. They are intentionally no longer copied into the current benchmark directory.
