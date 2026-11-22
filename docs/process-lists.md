# Process lists

A process list matches connections by the executable that opened them. Rules
reference it with a `process` condition. Each entry is one line; text after `#`
is a comment. The stored format is unchanged: an entry is a glob pattern when
it contains `*` or `?`, otherwise an exact path or name.

## Syntax

| Entry | Matches |
| --- | --- |
| `/usr/bin/curl` | Exactly this executable. |
| `*` | Any characters inside one path component. Never crosses a separator. |
| `?` | Exactly one character inside one path component. |
| `**` | Any number of directories. Must be a whole component (`/a/**/b`). |
| `/opt/app/**` | Every executable below `/opt/app`, at any depth. Not `/opt/app` itself and not `/opt/app-old`. |
| `**/aaa/**` | Every executable below any directory named exactly `aaa`, at any depth and under any root. |
| `com.example.app`, `:System` | A name reported instead of a path (Android packages, Windows pseudo processes), compared exactly. |

`**` at the end needs at least one component below the directory. Elsewhere it
also matches zero directories, so `/srv/**/tools/run` matches `/srv/tools/run`.

Examples:

```text
# macOS: the app and all of its helpers, renderers and GPU processes
/Applications/ExampleEditor.app/**
# the same bundle wherever it is installed
**/ExampleEditor.app/**
# Linux
/usr/lib/example-editor/**
# any directory named aaa
**/aaa/**
# partial names
**/Example*/bin/**
**/Example*/bin/helper?.exe
```

Rejected when the list is saved, with the line number:

| Entry | Reason |
| --- | --- |
| `**foo`, `foo**bar`, `/opt/app**` | `**` is not a whole component; use `*` inside a name. |
| `foo/**`, `chrome*` | A pattern must be absolute or start with `**/`. |
| `bin/curl` | A relative path can never match. |
| `/..`, `**/../x` | `..` above the root or after a wildcard. |

Character classes (`[abc]`) and braces (`{a,b}`) are not special: they are
matched as literal text. There is no escape character.

## Windows

Windows paths accept `\` and `/` and are compared without regard to case.

```text
# C drive only
C:\Program Files\ExampleEditor\**
# any drive or network share
**/Program Files/ExampleEditor/**
# any directory named aaa
**/aaa/**
```

The drive, UNC server and share, or device of a path is its *root*, not a path
component. A pattern with a root matches only that root; only a pattern that
starts with `**/` matches under any root. A pattern without a drive letter is
never widened to every drive:

| Entry | Result |
| --- | --- |
| `C:\Program Files\ExampleEditor\**` | C: only; also matches `c:\program files\…`, `C:/Program Files/…` and `\\?\C:\Program Files\…`. |
| `D:\…` path against a `C:\…` pattern | No match. |
| `\Program Files\ExampleEditor\**` | Rejected: no drive letter. Write `C:\…` or `**/…`. |
| `C:relative\path` | Rejected: drive-relative paths are not supported. |
| `*:\Program Files\**` | Rejected: wildcard drive letters; use `**/`. |
| `\\server\share\ExampleEditor\**` | That share only. |

Path forms are normalized before matching:

- `\\?\C:\…`, `\??\C:\…` and `\\.\C:\…` are the same as `C:\…`.
- `\\?\UNC\server\share\…` is the same as `\\server\share\…`. UNC paths never
  equal a local drive.
- `\Device\HarddiskVolume3\…` is translated to its drive letter using the
  device table read when the lists are applied. An unknown device stays a
  distinct root, so it matches only `**/` patterns and patterns naming that
  device; it is never guessed to be a drive.
- `.` and `..` components and repeated separators are removed lexically.

## macOS and Linux

Paths are compared case-sensitively on both, including macOS: APFS volumes can
be case-sensitive, and the kernel reports the on-disk spelling, so folding
would only risk matching a different executable. `/Volumes/…` paths are
ordinary paths.

On Linux, the kernel appends ` (deleted)` to the executable path of a process
whose file was replaced or removed while it runs (common after package
upgrades). The suffix is ignored, so the process still matches its path.

Patterns are matched against the path the kernel reports, which already has
symbolic links resolved (`/proc/PID/exe` on Linux, `proc_pidpath` on macOS).
List the real location: `/usr/bin/python3` will not match if it is a link to
`/usr/bin/python3.12`. Links are not resolved while matching, so lookups never
touch the file system.

## Shared lists across platforms

A list may hold entries for several platforms. On Linux and macOS, Windows
paths (`C:\…`, `\\server\…`) are validated and then ignored; on Windows, Unix
paths starting with a single `/` are. Patterns starting with `**/` apply on
every platform.

## Process lookup

Process rules only match when the process is known:

- **Process lookup mode** `off` never looks up processes, so process rules never
  match. `rules_only` looks them up only while some process list has an entry
  that can match on this platform. `always` looks them up for every connection.
- When the operating system cannot attribute a connection to a process, or
  returns no path, the rule does not match. The process name alone is never
  used to guess.
- Connection details and history show the path exactly as the operating system
  reported it; normalization only affects matching.

## Invalid entries

Saving a local list rejects every invalid entry and names its line, and the web
editor shows the same problems before saving. A remote list cannot be checked
when it is saved: invalid lines are skipped when the lists are applied, and the
list is reported as an activation issue. Because a skipped entry could have
matched, the list then counts as incomplete: it can still prove that a process
matches, but rules using it are marked degraded. A staged configuration change
(see [configuration changes](configuration-changes.md)) that would activate a
list with invalid entries is refused, and the running rules are kept.

## Performance

Patterns are compiled when lists are applied, never per connection. Exact
entries are one map lookup. Each glob is indexed under its most selective
literal text, so a lookup only evaluates globs that share a directory or file
name with the path, independently of how many patterns exist. See
[process matcher benchmarks](benchmarks/process-matcher.md).
