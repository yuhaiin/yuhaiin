# CI builds

`.github/workflows/go.yml` defines the release targets and waits for every binary
and the Android AAR before publishing. It calls `build-binary.yml` for each of
the 22 binary targets:

| Job | Targets | Build environment | SQLite |
| --- | --- | --- | --- |
| `linux` | amd64, amd64v3, amd64v4, arm64, mipsle | Ubuntu with musl cross compilers | mattn, statically linked |
| `darwin` | amd64, amd64v3, amd64v4 | macos-15-intel with Apple's clang/SDK | mattn with CGO |
| `darwin` | arm64 | macos-15 with Apple's clang/SDK | mattn with CGO |
| `cross` | FreeBSD, OpenBSD, Windows: amd64, amd64v3, amd64v4, arm64; Android: arm64 | Ubuntu, CGO disabled | modernc |

The reusable binary workflow handles checkout, Go setup, frontend update,
toolchain setup, and artifact upload. Darwin's baseline amd64 and arm64 jobs
also run the SQLite storage, FakeIP, statistics, and legacy settings tests.
The v3/v4 binaries are built without executing them on runners that may lack
the required CPU instructions. Makefile's build-tag generator always runs with
`GOAMD64=v1`, independently of the target binary's CPU level.

`frontend-version.yml` resolves one frontend commit per workflow run. Both the
binary/AAR workflow and `container.yaml` use it so their parallel builds use
the same frontend revision within each run. Go versions come from `go.mod`.

## Shared build scripts

- `scripts/build/release.sh OS ARCH [OUTPUT_DIR]` selects Go architecture flags,
  CGO, SQLite tags, and linking settings, calls `make yuhaiin`, and names the
  binary `yuhaiin-OS-ARCH[.exe]`. When `GITHUB_OUTPUT` is set, it exports the
  `binary` path for artifact upload.
- `scripts/build/install-musl-toolchain.sh ARCH` downloads a pinned compiler,
  verifies its SHA-256 checksum, and prints the compiler path. It requires
  `RUNNER_TEMP` and runs on Linux. Update the release URL and checksums together.
  Binary and container builds share this installer and the release script.

Darwin uses SQLite's bundled C source, so users do not need Homebrew SQLite.
Only macOS system libraries/frameworks are dynamically linked. Its deployment
target is explicitly macOS 13.0, matching Go 1.27's minimum, so a newer runner
SDK does not raise the binary's minimum OS version. Review this target when
upgrading Go.

## Validation

`lint.yml` checks workflows with actionlint and build scripts with ShellCheck.
To run the same checks locally:

```sh
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
shellcheck scripts/build/install-musl-toolchain.sh scripts/build/release.sh
```
