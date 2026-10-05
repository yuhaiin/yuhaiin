# CI builds

`.github/workflows/go.yml` defines the release targets and waits for every binary
and the Android AAR before publishing. It calls `build-binary.yml` for each of
the 22 binary targets:

| Job | Targets | Build environment | SQLite |
| --- | --- | --- | --- |
| `linux` | amd64, amd64v3, amd64v4, arm64, mipsle | Ubuntu with musl cross compilers | mattn, statically linked |
| `darwin` | amd64, amd64v3, amd64v4, arm64 | Ubuntu 24.04 with osxcross/LLVM 18 and macOS SDK 14.5 | mattn with CGO |
| `windows` | amd64, amd64v3, amd64v4, arm64 | Ubuntu with llvm-mingw/UCRT cross compilers | mattn, compiler runtimes statically linked |
| `cross` | FreeBSD, OpenBSD: amd64, amd64v3, amd64v4, arm64; Android: arm64 | Ubuntu, CGO disabled | modernc |

The reusable binary workflow handles checkout, Go setup, frontend update,
toolchain setup, and artifact upload. Release jobs do not compile or run SQLite
test executables. The v3/v4 binaries are built without executing them on runners
that may lack the required CPU instructions. Makefile's build-tag generator always runs with
`GOAMD64=v1`, independently of the target binary's CPU level.

`test-windows.yml` runs the release executable's `version` command on native
Windows x64/ARM64 runners before publication. Each Windows build also verifies
the binary's architecture, CGO/mattn metadata, and system DLL imports.
The release job only downloads artifacts matching `yuhaiin*`.

`test-sqlite.yml` independently runs the SQLite storage, FakeIP, statistics, and
legacy settings regressions on Ubuntu with both mattn (CGO) and modernc. It runs
for Go source, module, or its workflow changes on main pushes and pull requests,
and can also be started manually. These tests do not gate binary publication.

`benchmark-sqlite.yml` is manual-only: select **Windows SQLite benchmarks** in
Actions and use **Run workflow**. It cross-compiles the statistics benchmarks for
both backends, runs them on native Windows x64/ARM64, and uploads the comparison
logs as `windows-benchmarks-ARCH`. Benchmark artifacts belong to that separate
workflow run and do not enter releases.

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
- `scripts/build/install-windows-toolchain.sh ARCH` downloads pinned llvm-mingw
  20260922, verifies its SHA-256 checksum, and prints the target compiler path.
  It supports Linux x64/ARM64 and macOS hosts and requires `RUNNER_TEMP`.
- `scripts/build/install-darwin-toolchain.sh ARCH` installs pinned osxcross with
  the LLVM build flavor and macOS SDK 14.5, verifying both archive checksums.
  It runs on Linux with LLVM 18 installed and requires `RUNNER_TEMP` (or an
  explicit `OSXCROSS_ROOT`). The workflow caches the installation for all four
  Darwin targets; its key includes the installer so version changes invalidate
  the cache. SDK packaging follows [osxcross's SDK documentation](https://github.com/tpoechtrager/osxcross/blob/master/README.SDK.md).
- `scripts/build/check-windows-binary.sh BINARY ARCH` verifies the PE/Go CPU target,
  CGO/mattn build metadata, and DLL imports. `LLVM_READOBJ` selects the tool from
  the installed toolchain. Non-system DLL dependencies fail the build.

Windows builds include SQLite's C source and statically link compiler runtimes,
so they remain single executables. They use the UCRT supplied with Windows 10+;
users do not need SQLite or MinGW installed.

Darwin is cross-compiled on Linux using [osxcross](https://github.com/tpoechtrager/osxcross).
It uses SQLite's bundled C source, so users do not need Homebrew SQLite.
Only macOS system libraries/frameworks are dynamically linked. Its deployment
target is explicitly macOS 13.0, matching Go 1.27's minimum, so a newer runner
SDK does not raise the binary's minimum OS version. Review this target when
upgrading Go.
Local builds on macOS continue to use the native compiler and SDK. Linux builds
require `CC` to select the osxcross compiler, whose wrapper supplies the SDK.

## Validation

`lint.yml` checks workflows with actionlint and build scripts with ShellCheck.
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
