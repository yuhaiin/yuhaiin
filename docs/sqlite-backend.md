# SQLite backend and Linux updates

Yuhaiin uses `github.com/yuhaiin/purego-sqlite`, backed by the official SQLite
engine. Configuration and management schemas are unchanged. Existing modernc
and mattn database files are opened directly; no export/import is needed.

CGO-disabled Go builds on Linux/macOS/Windows amd64/arm64 and FreeBSD amd64 select
the verified library embedded by `github.com/yuhaiin/purego-sqlite-embed`.
CGO-enabled builds link the official SQLite engine by default; race tests use
`-tags=sqlite_purego` to exercise PureGo with CGO enabled.
The embedded library includes the optional row and scalar execution helpers.
FreeBSD PureGo builds also require
`-gcflags=github.com/ebitengine/purego/internal/fakecgo=-std`.

Android, iOS, MIPS, OpenBSD and other targets without the selected embedded
library require CGO and a C compiler matching the target. SQLite's official
amalgamation is linked into the program, with no system SQLite dependency.
`-tags=sqlite_cgo` explicitly selects this linked engine on any platform. A normal CGO-enabled build therefore also works on Linux hosts that cannot
load the glibc library. A CGO-disabled build cannot provide this fallback and
reports the required build configuration.

For Alpine/musl or a loader-free container, build with a musl compiler:

```sh
CGO_ENABLED=1 CC=musl-gcc go build -tags=sqlite_cgo \
  -ldflags='-linkmode external -extldflags -static' ./cmd/yuhaiin
```

Linux release names preserve compatibility with already installed updaters:

| Asset | Engine | Runtime requirement |
| --- | --- | --- |
| `yuhaiin-linux-ARCH` | Static CGO SQLite, fully static musl executable | No system libc, loader or SQLite |
| `yuhaiin-linux-ARCH-glibc` | PureGo and embedded SQLite | glibc >= 2.17, amd64/arm64 |

`ARCH` includes the existing amd64v3/amd64v4 CPU levels. MIPS only publishes the
portable static form. Other desktop release names retain their existing form.
`release.sh linux amd64-glibc` builds the PureGo variant; the unsuffixed Linux
target uses the existing musl cross toolchain. Container builds remain static.

The new updater checks the host's libc ELF version definitions without running
system commands. It prefers `-glibc` only when the host loader and libc satisfy
the 2.17 baseline. Older glibc, musl and unknown environments select the static
asset. When a previous release has no PureGo variant, glibc hosts can still use
its portable static asset. The selected binary and its exact `.update.json`
remain bound to the existing checksums. The manifest format and CPU labels are
unchanged, so older updaters continue selecting the safe static Linux asset.
Before installation and protected replacement, the actual executable's Go
metadata, ELF loader and versioned libc dependencies are checked again; archived
rollback candidates receive the same checks.

Storage startup first inspects schema compatibility without changing journal
mode. Only after that check does a connector apply the journal, foreign-key,
busy timeout and synchronous settings to every new physical connection.
Management connections retain `synchronous=FULL`, including pool replacements.
Read snapshots enforce SQLite's `mode=ro`; transaction readers use a deferred
transaction for a consistent SELECT snapshot. Each Exec/Query contains one SQL
statement; trigger bodies remain intact.

Coverage includes old modernc/mattn configuration and management fixtures,
reconnect settings, cancellation, migrations, triggers/FTS/JSON, private file
permissions, authentication, FakeIP, statistics, committed WAL backups and
recovery. CI executes both backends, native desktop OS/CPU combinations, MIPS
under QEMU and BSD CGO inside native VMs. `scripts/build/test-linux-abi.sh` checks
real glibc 2.17, newer glibc, glibc 2.12, Alpine/musl and scratch environments,
including update selection and rejecting incompatible staged targets.
