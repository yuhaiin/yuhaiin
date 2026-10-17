# Native checksum acceleration

Date: 2026-10-17. Baseline: `bb04f0bc`, following the
[offload and ownership optimization](lightweight-offload-optimization-20261017.md).
This follow-up targets CPU efficiency without changing packet validation,
congestion control, buffer ownership, MTU or offload negotiation.

## Implementation and hardware scope

The amd64 path uses Go's `math/bits.Add64` intrinsics to accumulate 64-byte blocks
with end-around carry. The Go 1.27.2 compiler emits native ADD/ADC instructions;
a handwritten assembly prototype had essentially identical throughput and was
not retained. This needs only baseline x86-64 instructions, including on Intel
Macs and x86_64 Android emulators; no AVX/ADX feature assumptions are made.

The arm64 path uses a small Go assembly ASIMD/NEON loop, widening native 16-bit
words into independent 32-bit vector accumulators. Each call processes at most
64 KiB, bounding both lane accumulation and the horizontal reduction. That path
is shared by Linux/Android arm64 and Apple Silicon builds. QEMU executes its
functional tests; no physical arm64 performance gain is inferred from emulation.

Inputs smaller than 128 bytes and residual tails retain the portable Go loop.
IP/pseudo headers bypass the bulk dispatcher to preserve the leaf-call hot path.
Other architectures use that loop for the entire input. Architecture selection
is automatic; no custom `purego` build tag is required.
Complete 64-byte blocks avoid overreading; unaligned data is supported. Odd bytes,
network byte order, caller seeds and one's-complement zero are preserved.
Native-width accumulation and final folding/byte swapping follow
[RFC 1071 section 2](https://www.rfc-editor.org/rfc/rfc1071.html#section-2).
The production core still has no external dependencies.

Checksum acceleration does not replace transport checks with CRC32 or change the
trusted-kernel checksum boundary. Kernel partial-checksum/GSO records continue
using the existing offload path.

## Why the expected end-to-end gain is smaller

The previous GSO download profiles put 50-63% of proxy CPU samples in syscalls
and about 7-8% in memmove. Plain CUBIC download had about 3% flat checksum samples.
Accelerating checksum arithmetic therefore cannot remove most GSO CPU cost.
The runtime already provides architecture-tuned memory copying. Further GSO CPU
work should investigate syscall frequency, stream gathering and owned packet
vectors, with explicit lifetimes and accepted-byte accounting.

## Controlled amd64 microbenchmarks

Ryzen 5 5600G, Go 1.27.2, `-cpu=1`, five repetitions of 300 ms per size, sequential
native and portable runs without concurrent builds, tests, emulators or traffic.
Medians in ns/op; both paths allocate zero bytes:

| Input bytes | Portable Go | Native amd64 | Speedup |
|---|---:|---:|---:|
| 40 | 9.623 | 10.09 | 0.95x |
| 1500 | 221.0 | 62.03 | 3.56x |
| 65535 | 9175 | 2337 | 3.93x |

The 40-byte public API dispatch adds about 0.47 ns in this microbenchmark. The end-to-end
comparison below measures whether that affects actual packet workloads.

The discarded amd64 assembly prototype measured about 60.74 ns at 1500 bytes
and 2333 ns at 65535 bytes. A standalone Go carry prototype also matched it;
this did not justify maintaining handwritten amd64 assembly. Prototype records
are separately labeled and excluded from the final comparison.

## End-to-end A/B

Both binaries come from the same worktree. A temporary Go overlay replaces only
this package's native checksum dispatcher with the portable path for the
baseline; the candidate uses the native path. Both retain the direct portable
IPv4/pseudo-header path. Dependency build tags and
checkout files are unchanged. Each sample uses a fresh
rootless user/network namespace and independent client, tested proxy, common
SOCKS backend and target processes. The runner interleaves both binaries in
seeded randomized order, with the existing CPU affinities, GOMAXPROCS=3, MTU 1500,
one flow, three five-second samples per direction and packet mode. It records
received payload goodput and tested-proxy user+system CPU per decimal payload GB.
These are local unencrypted Linux stack/bridge measurements, not full application
or WAN performance. All 24 final samples and distributions are retained.

| Mode / direction | Portable Gbit/s | Native Gbit/s | Portable CPU s/GB | Native CPU s/GB |
|---|---:|---:|---:|---:|
| cubic / upload | 4.91 | 5.25 | 3.340 | 3.181 |
| cubic / download | 4.48 | 4.49 | 3.587 | 3.580 |
| gso-cubic / upload | 21.90 | 23.19 | 0.607 | 0.576 |
| gso-cubic / download | 18.45 | 17.72 | 0.707 | 0.743 |

Plain upload reduces proxy CPU/GB by about 4.8% and increases goodput by about
6.9%; plain download is essentially unchanged. GSO upload measures 5.1% less
CPU/GB, but GSO download measures 5.1% more CPU/GB and 4.0% less goodput.
These short GSO results do not establish a consistent benefit.

The preceding `header-dispatch-ab` run instead measured GSO upload CPU/GB 2.1%
higher and download 0.8% lower. The final implementation bypasses the bulk
API for IPv4 headers, whose maximum length is 60 bytes, in addition to pseudo
headers. Both variants in the final comparison include this short-header path.

A separate eight-second profiled GSO-download pair reversed the final short-run
result: portable/native CPU/GB was 0.762/0.715. Syscalls account for about 60/61%
of portable/native CPU samples and memmove about 10/7%; checksum arithmetic
is absent from the top 25 nodes. Profiling adds overhead, so this pair diagnoses
the bottleneck and cannot replace the unprofiled measurements.

A follow-up without profiling uses three 15-second samples per variant for
GSO download. Median portable/native goodput is 18.52/18.45 Gbit/s and CPU/GB
0.702/0.708 (+0.9%). Individual CPU/GB samples overlap (portable 0.701-0.714,
native 0.687-0.721). This longer check does not reproduce the 5% short-run
regression and still provides no evidence of a GSO gain. Its six samples are
retained as `gso-download-sustained-ab`, separately from the original table.

A faster checksum microbenchmark does not imply a comparable whole-stack gain.
The mixed GSO results are retained alongside the consistent plain-upload gain;
this change makes no claim of improved GSO throughput or physical arm64 speed.

## Validation and reproduction

Reference tests compare against gVisor checksums across odd lengths, all-ones,
random seeded data, all 64 byte alignments, block/bulk boundaries and 1 MiB inputs.
Guard-page tests fault on loads before or after the allowed input. Fuzzing covers
checksum contents and seeds. Overlay tests exercise the portable fallback independently.
The full repository suite and TUN race tests pass, along with the Linux kernel
interop/offload suites and workflow-pinned lint checks. An initial full-suite
attempt hit the existing TLS compatibility test's two-second loopback read
timeout while other validation was active. Its isolated rerun and subsequent
full-suite runs pass; the original failure is retained for inspection.

The ARM64 reference/guard tests and full core protocol suite execute under QEMU;
CI adds the ARM64 checksum/guard execution and portable/fuzz checks. Both 4 KiB
and 16 KiB guard-page tests pass under QEMU locally. The native x86_64 build
also passes the real Android API 35 VpnService fixture under SELinux Enforcing
and 16 KiB pages: MTU 1500 and 9000 each verify six 256 MiB transfers (3 GiB
combined). The framework FD remains plain TUN; no Android offload is assumed.
Core builds cover eleven OS/architecture pairs, including macOS and Android
arm64; adapter builds cover both macOS architectures, Android arm64 and Linux
386. These results establish compatibility, not physical arm64 performance.

```sh
go test ./pkg/net/proxy/tun/lightweight -run '^TestChecksum' -count=1
python3 scripts/benchmarks/checksum_portable.py test \
  ./pkg/net/proxy/tun/lightweight -run '^TestChecksum' -count=1
go test ./pkg/net/proxy/tun/lightweight -run '^$' \
  -fuzz '^FuzzChecksum$' -fuzztime=10s -parallel=4
go test ./pkg/net/proxy/tun/lightweight -run '^$' \
  -bench '^BenchmarkChecksum$' -benchtime=300ms -count=5 -cpu=1
python3 scripts/benchmarks/checksum_portable.py test \
  ./pkg/net/proxy/tun/lightweight -run '^$' \
  -bench '^BenchmarkChecksum$' -benchtime=300ms -count=5 -cpu=1

python3 scripts/benchmarks/checksum_portable.py build \
  -o /tmp/stackprobe-portable ./scripts/benchmarks/stackprobe
go build -o /tmp/stackprobe-native ./scripts/benchmarks/stackprobe
python3 scripts/benchmarks/hev_compare.py \
  --probe /tmp/stackprobe-portable --compare-probe /tmp/stackprobe-native \
  --hev-lib /path/to/hev/bin/libhev-socks5-tunnel.so \
  --stacks cubic gso-cubic --flow-counts 1 --samples 3 --seconds 5 \
  --output /tmp/checksum-ab.jsonl
```

Adjust CPU affinities to the host topology. Run builds, conformance tests and
emulators separately from performance sampling. QEMU timings are not hardware
benchmarks. [Raw samples and validation evidence](lightweight-results/checksum-native-20261017/)
include binary/source hashes, instruction output and separate exploratory
prototype measurements.
