# CI builds

`.github/workflows/go.yml` defines the build targets. Pull requests build twelve
representative binaries (Linux amd64/arm64 in static and glibc forms, MIPS,
macOS arm64, Windows amd64, FreeBSD amd64/arm64, OpenBSD amd64/arm64, and Android arm64)
and build the Android AAR. Full releases on `main` pushes and version tags wait
for all 26 binary targets and the Android AAR before publication:

| Job | Targets | Build environment | SQLite |
| --- | --- | --- | --- |
| `linux` | amd64, amd64v3, amd64v4, arm64, mipsle; four amd64/arm64 `-glibc` variants | Ubuntu with musl cross compilers for static assets | purego-sqlite: static CGO/musl or PureGo + embedded library |
| `darwin` | amd64, amd64v3, amd64v4, arm64 | Ubuntu, CGO disabled | PureGo + embedded library |
| `windows` | amd64, amd64v3, amd64v4, arm64 | Ubuntu, CGO disabled | PureGo + embedded library |
| `cross` | FreeBSD amd64, amd64v3, amd64v4 | Ubuntu, CGO disabled | PureGo + embedded library |
| `cross` | FreeBSD arm64 | Ubuntu with Clang, GNU ld.bfd, FreeBSD 14.3 sysroot | Official SQLite linked through CGO |
| `cross` | OpenBSD amd64, amd64v3, amd64v4, arm64 | Ubuntu with pinned LLVM and OpenBSD 7.8 sysroot | Official SQLite linked through CGO |
| `cross` | Android arm64 | Ubuntu with Android NDK | Official SQLite linked through CGO |

The reusable binary workflow handles checkout, Go setup, frontend update,
toolchain setup, and artifact upload. FreeBSD ARM64 and OpenBSD also cross-link
storage, FakeIP and migration test executables, without executing them on Linux.
The v3/v4 binaries are built without executing them on runners
that may lack the required CPU instructions. Makefile's build-tag generator always runs with
`GOAMD64=v1`, independently of the target binary's CPU level.

The binary workflow cross-compiles Windows releases on Linux and verifies the
binary's architecture, PureGo/embedded-library metadata, and system DLL imports.
It does not start a Windows runner or execute the release binary. The former
`pr-windows-test` and release `windows-test` jobs have been removed, including
their recovery/CLI startup checks and release dependencies. Independent SQLite
native-platform regressions remain in `test-sqlite.yml`; they do not replace the
removed release executable and CLI startup qualification.
The release job only downloads artifacts matching `yuhaiin*`.

`test-sqlite.yml` independently runs the SQLite storage, FakeIP, statistics, and
legacy settings regressions with PureGo, PureGo under the race detector and
fully static CGO, plus native desktop platforms, MIPS and Linux ABI checks. It runs
for Go source, module, or its workflow changes on main pushes and pull requests,
and can also be started manually. These tests do not gate binary publication.

Windows SQLite performance comparisons are still opt-in. In Actions, select
**SQLite regressions**, choose **Run workflow**, and enable the
`windows_benchmarks` input. This cross-compiles the statistics benchmarks for
both backends, runs them on native Windows x64/ARM64, and uploads comparison
logs as `windows-benchmarks-ARCH`. Benchmark artifacts do not enter releases.

`frontend-version.yml` resolves one frontend commit per workflow run. Both the
binary/AAR workflow and `container.yaml` use it so their parallel builds use
the same frontend revision within each run. Go versions come from `go.mod`.

All Go workflows use `.github/actions/setup-go`. It disables setup-go's combined
cache and separately caches the paths returned by `go env GOMODCACHE` and
`go env GOCACHE`:

- Module archives are shared by runner OS/architecture, Go version and the
  `go.mod`/`go.sum` hash. Release, AAR and container jobs also include the resolved
  frontend revision. A cache miss downloads the complete module graph before
  saving, so a small lint job cannot seed an incomplete shared module cache.
- Compiler outputs are scoped by runner image, Go version and build
  configuration. Each release OS/architecture, SQLite backend and auxiliary job
  has its own scope. Installer, build-script and cache-action changes also
  invalidate the prefix to cover pinned compiler/SDK updates. A new commit restores
  the previous snapshot via a prefix and saves the updated cache under its SHA
  and frontend revision; unchanged dependencies are checked and reused by Go.
  Exact hits on reruns do not upload another copy. CodeQL shares modules but
  does not restore ordinary compiler outputs for source extraction.

The previous setup-go key depended only on the runner, Go version and lockfile.
Parallel cross-builds and regression jobs restored the same archive, and an
exact hit skipped saving newly compiled packages. This made missing target
outputs get rebuilt on subsequent commits even though the log reported a hit.
Splitting the caches also avoids storing a module archive in every target's
compiler snapshot. Cache capacity and eviction still apply; compiler or source
changes still require recompilation, and release metadata normally requires
relinking. JSON v2 and Green Tea GC use Go 1.27's defaults.

## Shared build scripts

- `scripts/build/release.sh OS ARCH [OUTPUT_DIR]` selects Go architecture flags,
  CGO, SQLite tags, and linking settings, calls `make yuhaiin`, and names the
  binary `yuhaiin-OS-ARCH[.exe]`. When `GITHUB_OUTPUT` is set, it exports the
  `binary` path for artifact upload.
- `scripts/build/install-musl-toolchain.sh ARCH` downloads a pinned compiler,
  verifies its SHA-256 checksum, and prints the compiler path. It requires
  `RUNNER_TEMP` and runs on Linux. Update the release URL and checksums together.
  Binary and container builds share this installer and the release script.
- `scripts/build/check-windows-binary.sh BINARY ARCH` verifies the PE/Go CPU target,
  PureGo/embedded-library build metadata, and DLL imports. `LLVM_READOBJ` selects the tool from
  the installed toolchain. Non-system DLL dependencies fail the build.

Windows and Darwin releases embed SQLite's verified prebuilt library and use
PureGo. They do not require a cross C compiler or a system SQLite installation.

### FreeBSD ARM64 cross compilation

`scripts/build/install-freebsd-toolchain.sh arm64` installs the checksum-pinned
FreeBSD 14.3 base SDK and builds GNU binutils 2.45's ARM64 FreeBSD linker on Linux.
It prints a Clang compiler wrapper path. Install Clang, build-essential, bison,
flex and texinfo first; set `RUNNER_TEMP` to a writable scratch directory.
The workflow caches the installed SDK/linker, with a key including the installer
hash. Existing Go module/compiler caches also apply to this target.

```sh
CC=$(bash scripts/build/install-freebsd-toolchain.sh arm64)
export CC
bash scripts/build/release.sh freebsd arm64
bash scripts/build/check-freebsd-binary.sh yuhaiin-freebsd-arm64
```

This avoids compiling Go and SQLite inside an ARM VM emulated on x86. Go
[requires GNU ld.bfd for FreeBSD ARM64 external linking](https://github.com/golang/go/issues/35197);
Clang with an LLVM-only linker is insufficient. SQLite stays compiled into the
executable, with only FreeBSD libc, libthr and libm allowed as shared dependencies.
The release and three regression binaries are inspected for their ELF/Go target,
FreeBSD ABI note and loader, dependencies, undefined SQLite imports and host
library search paths. These checks do not execute ARM64 FreeBSD code; runtime
qualification requires an actual FreeBSD host.

### OpenBSD cross compilation

`scripts/build/install-openbsd-toolchain.sh ARCH` installs the official OpenBSD
7.8 headers, startup objects and system libraries from checksum-pinned `base78`
and `comp78` sets. It reuses the existing pinned native LLVM distribution from
`install-windows-toolchain.sh`, with an OpenBSD target and sysroot. Clang and LLD
23.1.2 support both amd64 and arm64, including the Go-required NOBTCFI header.
No compiler needs to be built from source. Set `RUNNER_TEMP` to a writable scratch
directory; `OPENBSD_CROSS_ROOT` optionally selects the installation directory.

```sh
CC=$(bash scripts/build/install-openbsd-toolchain.sh arm64)
export CC
bash scripts/build/release.sh openbsd arm64
bash scripts/build/check-openbsd-binary.sh yuhaiin-openbsd-arm64 arm64
```

The wrapper supplies unversioned library aliases for upstream LLD, preserving the
official library SONAMEs in the executable. It normalizes Go's native `-nopie`
spelling and merges startup-object Retguard cookies into `.openbsd.randomdata`.
LLD emits the RANDOMIZE and NOBTCFI program headers; immediate binding and RELRO
protect the random data and relocation tables after startup. The inspector
rejects orphan Retguard sections, missing security headers, random data outside
RANDOMIZE/RELRO, writable executable segments, host search paths and shared SQLite.
Only the SDK's libc, libpthread and libm may remain shared.

The workflow caches the SDK and LLVM by host, target architecture and installer
hash; amd64/v3/v4 share one SDK cache. Go module/compiler caches also apply. Normal
release builds run entirely on Linux. Cross-linked test binaries validate build
and link compatibility; executing them requires an OpenBSD host.

Initial qualification on 2026-11-04 executed the Linux-built storage, FakeIP and
migration tests plus the release's `version` command on OpenBSD 7.8
[amd64](https://github.com/yuhaiin/yuhaiin/actions/runs/41855486241/job/126668220903)
and [arm64](https://github.com/yuhaiin/yuhaiin/actions/runs/41855486241/job/126668612096).
Both passed. The temporary execution VMs were then removed from the workflow.
The first uncached Linux builds took 3m46s for amd64 and 4m11s for arm64,
including SDK/LLVM installation and all binary inspections.

## Validation

`lint.yml` combines formatting, Go fixes, actionlint and ShellCheck in one
static-check job; SSR, SSH and VPN race tests also share a runner. It keeps
their existing commands and test coverage while avoiding redundant setup.
To run the same checks locally:

```sh
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
shellcheck scripts/build/*.sh
```

### Go cache validation (2026-10-05)

The [baseline run](https://github.com/yuhaiin/yuhaiin/actions/runs/37285861254)
restored the same ~298 MiB Go cache in Darwin, Windows and Linux cross-builds;
the [SQLite regression run](https://github.com/yuhaiin/yuhaiin/actions/runs/37285860852)
also restored that key. Their post steps reported an exact hit and skipped
saving. The Android AAR restored a separate ~25 MiB cache based on `go.mod`,
then also skipped saving its new compiler outputs. Repository cache usage was
10,348,002,272 bytes across 56 entries at inspection time; this is a snapshot,
not a guarantee of retained capacity.

Local validation passed actionlint v1.7.12, ShellCheck for the composite action,
and `go mod download` without changing module files. Cache-key checks covered
all 32 active compiler scopes: different targets/backends get different keys,
module archives remain shared, new commits/frontends save a new snapshot, and
Go version, runner image or installer/SDK changes invalidate the compiler prefix.

A separate Go 1.27.1 source copy was built with an empty GOCACHE, its cache was
archived and restored into another empty directory, then a codec declaration
was changed to check invalidation:

| Local domain trie package build | Packages compiled | Elapsed |
| --- | ---: | ---: |
| Empty cache | 71 | 2.036 s |
| Restored archive, unchanged source | 0 | 0.039 s |
| Restored archive, changed codec | 2 (codec and domain disk) | 0.079 s |

This validates Go's compiler-cache reuse and invalidation, not GitHub service
restore/save behavior or hosted-runner speed. The new keys initially require a
cold build. After deployment, compare two different commits with the same
target: `Restore Go build cache` should report a prefix restore, the post step
should save the new SHA key, and `go build -v` should list fewer unchanged
packages. Downloading toolchains, generating Android bindings and relinking
release metadata can still take time even with a warm Go compiler cache.
