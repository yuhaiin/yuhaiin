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

`build-binary.yml` explicitly enables setup-go's module/build cache, keyed by
`go.sum`. The independent regression and benchmark workflows also enable this
cache. JSON v2 and Green Tea GC use Go 1.27's defaults.

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
