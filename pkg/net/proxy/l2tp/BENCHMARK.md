# L2TP container benchmark samples

Measured on 2026-10-11 with an AMD Ryzen 5 5600G, Linux 7.2.6-zen2 and rootless Podman. The runner executes an uninstrumented userspace client in a separate host process, with the echo worker and tunnel peer in isolated containers. All seven cases also passed race-enabled IPv4/IPv6 TCP/UDP interop where supported.

Each entry is the median and range of three 2-second samples, in MB/s of payload per round trip (one request payload counted). TCP sends and echoes 256 KiB per iteration; UDP sends and echoes 1200 bytes. These are local container/network-stack measurements, not remote encrypted throughput or a comparison between protocols.

| Peer / mode | TCP median (range), MB/s | UDP median (range), MB/s |
| --- | ---: | ---: |
| SoftEther / pap | 3.89 (3.80–3.97) | 5.07 (5.03–5.08) |
| SoftEther / mschap-v2 | 4.17 (3.26–4.33) | 3.43 (2.16–4.97) |
| Linux L2TPv3 / none | 7.72 (4.74–10.77) | 8.34 (8.31–8.34) |
| Linux L2TPv3 / 4-byte cookie | 6.53 (6.39–9.60) | 8.27 (7.70–8.36) |
| Linux L2TPv3 / 8-byte cookie / sublayer | 12.31 (10.99–15.09) | 7.54 (6.47–8.24) |
| Linux L2TPv3 / dynamic / sublayer | 11.97 (11.50–13.41) | 8.16 (8.16–8.20) |
| Linux L2TPv3 / dynamic / authenticated | 8.28 (5.10–13.32) | 8.14 (8.06–8.16) |

SoftEther 4.43 uses userspace SecureNAT. Linux owns the L2TPv3 Ethernet data channel; the dynamic cases use an independent Python control peer. TCP sample ranges show substantial local timing variance, so use these as reproducible baseline samples rather than performance guarantees. Stock xl2tpd/pppd needs accessible `/dev/ppp`; its interoperability matrix runs in Docker CI and is not included in these rootless benchmark samples.

Reproduce with:

```sh
python3 scripts/bench/l2tp/run.py --runtime podman --benchmark --output /tmp/l2tp.json
```
