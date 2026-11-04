# CI coverage

Keep ordinary package tests in `workflows/tests.yml`. Its network, gateway and
application groups have disjoint package lists; add a package to one group only.
MASQUE runs separately with `-p 1` because its PMTU tests depend on network timing.
The application group installs Node.js for the Web Crypto interoperability tests.

Specialized coverage stays separate:

| Workflow | Coverage |
| --- | --- |
| `lint.yml` | Formatting, Go fixes, actionlint, shellcheck and golangci-lint |
| `tests.yml` | Default race tests, release-tag DNS and nil-connection tests, dependency boundaries |
| `test-sqlite.yml` | PureGo embedded and static CGO, application persistence/identity/recovery, native desktop CPUs, MIPS QEMU, and glibc/musl ABI/update selection |
| `lightweight-stack.yml` | Portable checksum fallback, Linux kernel peers, all eight portable core targets, three cross-platform test builds, ARM64 QEMU |
| `reliability.yml` | Real installed-service recovery and protected-update drills for system and user services |
| `ssh-session.yml` | Native Linux SSH isolation with TUN and cgroup v2 |
| `profiler.yml` | Native macOS and Windows profiler behavior; Linux is covered by the application group |
| Protocol interop workflows | Real independent protocol implementations and container fixtures |

`go.yml` cross-compiles Windows releases on Linux and checks PE architecture,
PureGo/embedded-library metadata and system DLL imports. It has no native Windows
release executable or CLI recovery/startup qualification job. Independent native
Windows SQLite/profiler regressions and optional performance workflows remain.

Do not repeat ordinary `go test -race` commands in interop workflows. Build tags,
CGO settings, native operating systems and privileged fixtures provide additional
coverage and must not be removed just because they exercise the same package.
When narrowing path filters, include shared dependencies and fixture data as well
as the protocol implementation. In particular, portable test builds import shared
packages outside the TCP/IP stack itself.

`performance.yml` runs weekly and can be dispatched manually. It owns scheduler,
application, recovery and Windows durability benchmarks, the complete stack
benchmark smoke suite, sustained BBR qualification, 100-run SACK stability,
25-run kernel device lifecycle checks and active parser/classifier fuzzing.
Ordinary PR race tests still execute regression tests and fuzz seed cases once.
Linux and Windows benchmark logs are retained as artifacts for 14 days.

Validate workflow edits with:

```sh
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/*
git diff --check
```

To run a race group locally, use its `matrix.include[].packages` list from
`tests.yml` with `go test -race -count=1 -timeout=10m`. Native and privileged
checks require their matching operating system and kernel facilities.
