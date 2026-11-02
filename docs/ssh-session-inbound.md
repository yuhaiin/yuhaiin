# Linux SSH inbound (experimental)

Yuhaiin can accept SSH public-key logins and run a shell or an SSH `exec`
command inside a Linux network namespace. Traffic originating from commands
goes through an isolated TUN FD into Yuhaiin's existing lightweight TCP/IP
stack and normal inbound routing, including UDP and DNS interception.

This is **not** a general security sandbox. The session still shares the host
filesystem and process namespace. Do not enable it for untrusted identities
or on multi-tenant hosts before adding filesystem isolation and cgroup cleanup.

## Requirements

- Linux host (not Android) with `CAP_SYS_ADMIN`, `CAP_NET_ADMIN` and `/dev/net/tun`.
- A dedicated, unprivileged Linux UID and GID with filesystem permissions
  suitable for the intended commands.
- An authorized SSH public key. The server creates and persists an Ed25519  host key automatically when the SSH inbound is first saved.
- An explicit `allowUnsafeShell: true` acknowledging that filesystem and
  Unix-domain socket access is not isolated.

No networking CLI is executed. The dependency
[sessionnet](https://github.com/yuhaiin/sessionnet) configures a private per-connection network namespace, resolver, TUN, routes and lifecycle through Netlink/syscalls.

## Inbound configuration

Submit an inbound through the existing inbound API with a TCP-only network
and no transports:

```json
{
  "id": "ssh-session",
  "name": "SSH session",
  "enabled": true,
  "network": {
    "type": "tcp_udp",
    "tcp_udp": { "host": "127.0.0.1:2222", "udp": "tcp_only" }
  },
  "transports": [],
  "protocol": {
    "type": "ssh",
    "ssh": {
      "username": "alice",
      "authorizedKey": "ssh-ed25519 AAAA... alice@host",
      "uid": 65534,
      "gid": 65534,
      "shell": "/bin/sh",
      "sftpReadOnlyPaths": ["/srv/archive", "/srv/backups"],
      "mtu": 1500,
      "ipv6": true,
      "maxSessions": 8,
      "allowUnsafeShell": true
    }
  }
}
```

Replace the sample authorized public key and account IDs. The server generates an Ed25519 host key on the first save and preserves it across subsequent edits and restarts. A supplied `hostKey` overrides automatic generation. Keep SSH host private keys out of public logs and exports. Use a restricted listening address
or a suitable firewall; exposing arbitrary remote shell access is sensitive.

## Session addressing and FakeIP

The default IPv4 gateway and guest interface are `172.31.254.1` and
`172.31.254.2/30`. The default IPv6 pair is `fd42:7d2a:9b31::1` and
`fd42:7d2a:9b31::2/64`, outside the default FakeIP and Tailscale
address spaces. Inbound startup rejects overlap with the active FakeIP pools.
The SSH protocol configuration can override `gatewayIPv4`, `sessionIPv4`,
`gatewayIPv6` and `sessionIPv6` as needed.

## Crash-safe process containment

Each SSH inbound now requires cgroup v2 process containment. On startup the
server takes an exclusive lock on its dedicated cgroup subtree and uses
`cgroup.kill` to clean up processes left behind by a previous crash. The
namespace owner and all shell/exec commands are atomically placed in the
same cgroup using `CLONE_INTO_CGROUP`. Detached child processes cannot
escape termination merely by creating another process group.

By default the root is
`/sys/fs/cgroup/yuhaiin/ssh/<stable-inbound-hash>`, derived from the inbound
ID. The process must have permission to create and manage this path on a
writable cgroup v2 filesystem. Systems using systemd may require a delegated
subtree, in which case configure `cgroupRoot` under the SSH protocol to use
a **stable, dedicated** directory for that inbound. A normal disk directory,
read-only cgroupfs, missing `clone3` support, or an unrecoverable orphan
prevents the SSH listener from starting; no best-effort fallback is used.

This provides process containment, **not** filesystem isolation or protection
from host Unix-domain sockets. Test permissions before exposing SSH remotely.

## Behavior and limits

- Public-key authentication only. Password authentication, `direct-tcpip`
  port forwarding, SSH agent forwarding, and remote TCP listening are disabled.
- Supports SSH `session` channels with `shell`, `exec`, the built-in `sftp`
  subsystem, PTY allocation and terminal resize.
- The first shell or exec channel in an authenticated SSH transport creates one
  namespace, TUN, and lightweight stack. Concurrent channels on that SSH
  transport reuse them, including the isolated loopback network. Separate SSH
  transports never share a namespace, even when using the same SSH identity.
- Each running shell/exec command retains its own process group, PTY, standard
  I/O, and exit status. A lease keeps the shared network alive; the last
  command releasing its lease closes the namespace owner, TUN, and stack.
  A later command on the same SSH transport creates a fresh shared network.
- The host routing table is not changed. IPv4/IPv6 and DNS queries are delivered
  to the same Yuhaiin inbound handler used by TUN and WireGuard listeners.
- The first command must successfully create and connect the shared TUN and
  lightweight stack before any command can start. On failure, execution is rejected rather
  than falling back to ordinary host routing.
- Cancelling the SSH connection shuts down its session. Required cgroup v2
  containment also terminates detached descendants.
- This initial version has its own configured SSH public-key identity. It does
  **not** claim integration with the management user's credential and identity
  system. Setting the inbound `authentication` field is rejected.

## User home and shell startup

`HOME`, `USER`, `LOGNAME`, and the initial working directory follow the local
system account selected by `uid`, rather than the SSH authentication username.
If its home directory is missing, the working directory falls back to `/`.
An unregistered numeric UID uses `/` as HOME and the configured SSH username.

Leaving `shell` empty selects the local account's login shell, with `/bin/sh`
as fallback for missing entries or service accounts using `nologin`/`false`.
Existing explicit shell settings are preserved. The shell starts as a login
shell: select `/bin/bash` when Bash behavior is intended. `/bin/sh`, even when
it points to Bash, uses different startup files. Bash login shells read their
normal profile files; `.bash_profile` or `.profile` can source `.bashrc`.

## Built-in SFTP and read-only directories

SFTP is available on the same SSH listener, with the same public-key identity
and Linux UID/GID. It re-executes the Yuhaiin binary in an unprivileged child
using the existing shared namespace, cgroup, session limit and disconnect
cleanup. An external OpenSSH `sftp-server` executable is not required. SFTP
requests with a PTY or an unknown subsystem name are rejected.

`sftpReadOnlyPaths` is an optional list of absolute paths. If omitted or empty,
SFTP uses normal operating-system permissions. Each listed directory and its
descendants remain readable but reject uploads, appends, truncation, directory
creation, deletion, metadata changes, and renames into or out of the tree.
Moving an ancestor directory is rejected too. Symbolic-link targets are
resolved before writes; hard-link creation from a protected path is rejected.
Writable sibling directories remain governed by their normal permissions.

These are SFTP path rules. They do not modify host permissions, restrict SSH
shell/exec, or establish a filesystem sandbox. Pre-existing hard links outside
the configured paths retain their path's normal permissions. Use system
account/filesystem permissions when access must be restricted across all
applications and aliases.

The SSH editor exposes the read-only directory list, with one absolute path
per line. Leave it empty to retain the original filesystem permissions.

## Validation

Run the regular package checks with:

```sh
go test -race -count=1 -timeout=180s ./pkg/net/proxy/sshserver ./pkg/contract/inbound ./pkg/inbound
```

The privileged Linux integration tests are opt-in. They exercise an actual SSH
exec through the network namespace, verify IPv4/IPv6 TCP and UDP routing, query
the configured DNS gateway over UDP and TCP, and check that concurrent channels
share a namespace only within one SSH transport:

```sh
YUH_SSH_SERVER_INTEGRATION=1 go test -race -count=1 -timeout=120s ./pkg/net/proxy/sshserver
```

The integration suite also verifies SFTP upload/download, read-only denial,
shell access to the same files, reconnect/disconnect cleanup, and UID-based
HOME and working-directory selection. Set `YUH_SSH_SERVER_CGROUP_ROOT` to a
writable delegated cgroup v2 directory when running the production path.

For process/network qualification in disposable user namespaces without a
delegated cgroup (this exercises the test-only unmanaged server constructor):

```sh
go test -c -o /tmp/yuhaiin-sshserver.test ./pkg/net/proxy/sshserver
unshare --user --map-auto --map-root-user --mount --net sh -c '
  ip link set lo up && YUH_SSH_SERVER_NAMESPACE_TEST=1 \
    /tmp/yuhaiin-sshserver.test -test.run "^TestSSHServer(SFTP|UsesSystemHome)" -test.v
'
```

Measure SFTP protocol and filesystem costs, comparing default permissions
with a configured read-only policy, using:

```sh
go test -run '^$' -bench '^BenchmarkSFTP(Transfer|Read)$' -benchmem -benchtime=1s -count=3 -cpu=1 ./pkg/net/proxy/sshserver
```

These benchmarks transfer 32 KiB per operation over an in-process connection
to local temporary files. They exclude SSH encryption and real-network costs.

On Go 1.27.3, Linux amd64 and Ryzen 5 5600G, the median of three two-second
runs was:

| Operation | System permissions | Read-only path policy |
| --- | ---: | ---: |
| Read 32 KiB | 18.045 us/op, 15 allocs | 18.187 us/op, 15 allocs |
| Write 32 KiB to an unlisted path | 13.353 us/op, 16 allocs | 17.786 us/op, 22 allocs |

The write policy rechecks the opened file before each write, adding about
4.4 us per 32 KiB operation in this local benchmark. Raw output is in
`docs/benchmarks/ssh-sftp-2026-11-02.txt`.

Compare fresh SSH transports, a new namespace on a reused transport, and an
extra concurrent channel sharing a live namespace with:

```sh
YUH_SSH_SERVER_INTEGRATION=1 go test -run '^$' -bench '^BenchmarkSSHServerNetworkReuse$' -benchmem -benchtime=1s -count=3 -cpu=1 ./pkg/net/proxy/sshserver
```

Measured locally on Go 1.27.3, Linux amd64, and an AMD Ryzen 5 5600G. Each
row is the median of three one-second runs; all SSH traffic stays on loopback.
These are command and namespace lifecycle costs, not proxy throughput.

| Scenario | Time/op | B/op | Allocs/op |
| --- | ---: | ---: | ---: |
| New SSH transport and namespace | 34.78 ms | 364,827 | 1,343 |
| Reused transport, new namespace | 33.65 ms | 267,200 | 662 |
| Concurrent command, shared namespace | 1.06 ms | 108,951 | 232 |

The end-to-end checks need a Linux runner with TUN and namespace privileges.
They are available for local qualification; CI still needs a privileged job
before the feature can leave experimental status.
