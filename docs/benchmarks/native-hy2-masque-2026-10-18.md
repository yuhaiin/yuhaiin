# Native HY2 and MASQUE review measurements (2026-10-18)

Apple M4, macOS arm64, Go 1.27.2. These measurements cover the replacement HY2 implementation and local MASQUE HTTP/2 framing. They do not establish WAN throughput, phone battery use, real-utun performance, or live Cloudflare WARP interoperability.

## Correctness repairs

- HY2 TCP streams remain owned by the inbound handler after dispatch. Previously a channel/asynchronous handler received a stream whose sending side was immediately closed by the protocol dispatcher.
- HTTP/3 CONNECT setup observes cancellation while waiting for response headers, not only while opening the stream. Closing CONNECT-IP also cancels blocked QUIC datagram reads.
- HTTP/2 setup/header writes observe cancellation; send-window updates and SETTINGS cannot exceed the protocol's signed 31-bit flow-control bound. Failed PING/RST writes terminate the connection.
- HTTP/2's outer TCP connection uses the project dialer, preserving interface binding, socket protection/routing marks and interface loop prevention. A regression rejects a skipped interface before attempting the outer connection; the previous plain `net.Dialer` bypassed that protection.
- The HTTP/2 request-body buffer enforces its 32 KiB bound even on a single large write, supports partial writes/deadlines, and wakes blocked writers on close. Ring storage avoids moving all remaining bytes after every small read; deadline resets reuse a timer.
- HY2 UDP encoding reuses a bounded pooled buffer across fragments. Per-session packet IDs advance instead of using random IDs forced into half of the 16-bit namespace. QUIC copies accepted datagram payloads before returning, so returning the encoding buffer to the pool is safe.

The new regressions failed against the original implementation for TCP handoff, oversized body writes, blocked datagram reads, CONNECT response cancellation, blocked HTTP/2 HEADERS writes, window overflow and packet-ID preservation. They pass with the repairs. The HTTP/2 TCP fixture echoes more than 6 MiB using a deliberately small 1024-byte send window, covering split capsules and both flow-control windows.

## Component benchmarks

Same benchmark fixtures before/after the repair, `-cpu=1 -count=5 -benchtime=500ms`; medians below. HY2 uses an in-memory datagram sink that copies each accepted fragment, excluding QUIC encryption, network I/O and reassembly. The buffer case writes 32 KiB then reads it in 1200-byte pieces. Pool warmup is amortized.

| Workload | Before ns/op | After ns/op | Before B/op, allocs/op | After B/op, allocs/op |
| --- | ---: | ---: | ---: | ---: |
| HY2 encode 1000 B | 140.1 | 43.39 | 1080, 4 | 0, 0 |
| HY2 encode/fragment 8192 B | 2159 | 462.6 | 19240, 34 | 360, 2 |
| HY2 encode/fragment 65535 B | 15098 | 3019 | 151296, 230 | 3080, 2 |
| HTTP/2 buffer, small reads | 4271 | 816.5 | 0, 0 | 0, 0 |

The local HTTP/2 capsule echo benchmark measured median **33.8 us/1200-byte round trip**, **2858 B/op, 12 allocs/op**, including both peers' HTTP/2 framing and loopback TCP. Its deliberately constrained window and absence of TLS make it unsuitable as a Cloudflare throughput estimate. It has no prior HTTP/2 transport on main for comparison.

Allocation reductions reduce transient allocator/GC work. Pooling can retain reusable storage; these allocation figures do not imply the same reduction in process RSS.

## usque compatibility follow-up

The Cloudflare implementation was additionally compared with [usque `6aa03fc9`](https://github.com/Diniboy1123/usque/tree/6aa03fc97d12848dce34eedbd187fb1077b5d1ea) and its pinned CONNECT-IP adapter. Cloudflare H2 now configures receive routes locally, sends only type-0 DATAGRAM capsules containing raw IP, and skips non-DATAGRAM capsules. It uses ordinary CONNECT without requiring the extended-CONNECT setting. A real TCP fixture reproduces the previous unwanted ROUTE_ADVERTISEMENT and checks both IPv4 and IPv6 framing after repair.

H3 retains **BBR standard by default** and enables QUIC path MTU discovery instead of fixing the outer packet size at 1242 bytes. Real loopback H3 fixtures run through the default BBR connection setup over IPv4 and IPv6, verify matching outer socket families, discover enough MTU and echo a 1280-byte IPv6 packet. The previous fixed-MTU configuration fails this test. These fixtures do not authenticate to Cloudflare.

The send queue now reserves header space to avoid allocating/copying a second CONNECT-IP payload. Five paired component runs on the same host measured median **133.0 ns/op, 1280 B/op, 1 alloc/op** for the copying API and **23.73 ns/op, 0 B/op, 0 alloc/op** for the headroom API (1200-byte IPv4). This measures encoding only, excluding encryption, sockets and process RSS. Raw `masque-headroom-before.txt` and `masque-headroom-after.txt` retain the samples. Bounds, fallback, IPv4 options/checksum and IPv6 hop limit have regression coverage.

The follow-up passed five-repeat MASQUE race tests, the supported full-repository suite with the same host exclusions, Linux full lint, affected-package Darwin lint, clean go fix, and Android/Windows protocol builds. See [MASQUE transport documentation](../masque.md) for endpoint/pin configuration and upstream MIT attribution.

## Process CPU and RSS

The process-isolated HY2 harness was extended with optional `--resources` sampling (`psutil`, 20 ms interval, Linux/macOS). Each row below is the median of three measurements. TCP verifies 256 MiB per measurement, split across one or four streams. UDP sends 4000 x 1000 B at 5000 packets/s (40 Mbps offered). Every peer has `GOMAXPROCS=4`; target, server and workload/client are separate processes on IPv4 loopback.

CPU seconds are user+system time during the command, including client setup and verification. RSS is a **sampled process peak**, not the OS high-water mark, live Go heap or cumulative allocation. Persistent server CPU uses before/after deltas; workload CPU is collected when the child exits. These costs include the harness's forwarding path.

Native server + native client after repair:

| Workload | Mbps | Server CPU seconds | Client CPU seconds | Server sampled peak MiB | Client sampled peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| TCP upload, 1 stream | 1604 | 3.377 | 3.010 | 32.1 | 31.4 |
| TCP download, 1 stream | 1981 | 2.360 | 2.613 | 32.3 | 31.8 |
| TCP upload, 4 streams | 1374 | 3.779 | 3.226 | 33.5 | 31.8 |
| TCP download, 4 streams | 2375 | 2.011 | 2.367 | 33.5 | 32.7 |
| UDP echo, 40 Mbps offered | 40.0 | 0.277 | 0.264 | 32.5 | 30.8 |

The corresponding main baseline (`d6c071d6`, upstream Core/Extras) had roughly 31–34 MiB RSS for the same native/native workloads. The native implementation did not show a large RSS increase in this bounded run. This is not a long-duration leak test.

Whole-run CPU/throughput attribution is inconclusive: the main and repaired runs were sequential, with tests/lint overlapping portions of the runs. Even the unchanged official-server/official-client control dropped from 1416 to 1287 Mbps upload and 1683 to 1376 Mbps download (one stream), while consuming more CPU. The native/native drop therefore cannot be separated from machine/load effects. Retain these as resource snapshots, not evidence of an overall speedup or regression. The isolated component comparisons above are the evidence for the optimizations.

All 48,000 UDP echoes in the repaired BBR resource matrix arrived intact. The baseline lost 74/4000 packets in one native-server/official-client sample (1.85%); no payload corruption was observed. UDP is unreliable and this single difference is not a reliability-rate claim.

## Interoperability and validation

- Official Hysteria **2.13.0**, darwin-arm64 binary SHA256 `c8c3589239ce4ecf335c07a3f6ec11b3ef8fbdfe9e5a5ea0ef8ba8ce50d2bb90` (verified against the release asset digest).
- Before repairs: eight native/official pairings across BBR, 200 Mbps Brutal and Salamander, three repetitions, one/four-stream TCP upload/download and UDP echo completed (120 measurements).
- After repairs: all eight pairings passed TCP upload/download and **3000-byte fragmented UDP** echo (24 measurements; 800/800 UDP replies, zero corruption/loss). Native/native additionally passed an 8192-byte experiment and the package regressions cover larger payloads. An 8192-byte experiment via the official client returned no echoes; the old upstream Core's UDP serialization buffer is 4096 bytes, so the retained official-client fragmentation matrix uses 3000 bytes. Do not infer official-client support for 8 KiB datagrams.
- Race tests passed for HY2, MASQUE/CONNECT-IP, node contracts and registration; repeated cancellation/lifecycle cases and the inbound TLS compatibility matrix also passed.
- This Mac cannot bind the pre-existing address-hopping fixtures on `127.0.0.2/3`; `TestAddressHopSocketLifecycle` and `TestAddressHoppingKeepsTCPAndUDPSessions` were excluded locally. The Linux HY2 workflow runs them without exclusions.
- Full repository tests were attempted. Unrelated host failures: `TestDial/prefer_ipv6` (`::2` timeout), NetworkManager `TestNM` (no system D-Bus), and the 60000-byte `TestNATLargeUDPReply` (macOS `message too long`). The first heavily concurrent run also hit an inbound TLS test's two-second deadline; that matrix subsequently passed ten times under race and on the second full run.
- The full repository suite passed with `-skip '^(TestAddressHopSocketLifecycle|TestAddressHoppingKeepsTCPAndUDPSessions|TestDial|TestNM|TestNATLargeUDPReply)$'`. The exclusions are explicit host limits, not a claim that the unfiltered suite is green on this Mac.
- Linux-target full-repository golangci-lint **v2.15.0** passed. Native Darwin full lint reports existing unused Linux-offload declarations in `vpnkit/dataplane`; affected-package Darwin lint passes. `go fix` and formatting checks were run. Android arm64 and Windows amd64 pure-Go builds of both protocol packages passed.
- Cloudflare WARP H3/H2 authentication remains unverified with live credentials; local fixtures do not establish that compatibility. MASQUE workflow filters now cover main and shared congestion-control/node-contract changes after consolidation.

## Reproduction and raw samples

```sh
go test -race -count=1 ./pkg/net/proxy/hysteria2/... ./pkg/net/proxy/masque/...
go test -run '^$' -bench BenchmarkNativeDatagramEncoding -benchmem -cpu=1 -count=5 -benchtime=500ms ./pkg/net/proxy/hysteria2
go test -run '^$' -bench BenchmarkStreamBufferSmallReads -benchmem -cpu=1 -count=5 -benchtime=500ms ./pkg/net/proxy/masque/connectip
go test -run '^$' -bench BenchmarkHTTP2CapsuleTunnel -benchmem -cpu=1 -count=5 -benchtime=500ms ./pkg/net/proxy/masque
go test -run '^$' -bench BenchmarkPacketEncoding -benchmem -cpu=1 -count=5 -benchtime=500ms ./pkg/net/proxy/masque/connectip
python3 scripts/bench/hysteria2/run.py --official /absolute/path/to/hysteria --output /tmp/interop.json --smoke-only --udp-size 3000
python3 -m venv /tmp/hy2-resources
/tmp/hy2-resources/bin/pip install psutil
/tmp/hy2-resources/bin/python scripts/bench/hysteria2/run.py --official /absolute/path/to/hysteria --output /tmp/resources.json --scenario bbr --bytes 268435456 --repeats 3 --udp-packets 4000 --udp-pps 5000 --resources
```

Raw benchmark output, full process snapshots and the final interoperability matrix are retained under [data/native-hy2-masque-2026-10-18](data/native-hy2-masque-2026-10-18/).
