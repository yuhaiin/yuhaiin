# Linux SSH inbound (experimental)

Yuhaiin can accept SSH public-key logins and run a shell, an SSH `exec`
command or the built-in SFTP server inside a private network environment.
Traffic from those commands goes through a TUN device inside that
environment into Yuhaiin's lightweight TCP/IP stack and the normal inbound
routing pipeline, including UDP, DNS interception and FakeIP.

This is **network isolation, not a security sandbox.** Sessions share the
host filesystem, filesystem Unix-domain sockets and everything the shell
account can access. See [Security](#security) before enabling it.

## Namespace modes

| | `rootless` (default, recommended) | `rootful` |
|---|---|---|
| Yuhaiin runs as | any normal Linux user | root |
| Host capabilities needed | none (no `sudo`, no `setcap`) | `CAP_SYS_ADMIN`, `CAP_NET_ADMIN` |
| Namespaces | user, network, mount, PID | network, mount, PID |
| Shell UID/GID (host IDs) | Yuhaiin's own account; any UID/GID if Yuhaiin is host root; IDs of its namespace if Yuhaiin is root of an inherited one (Podman); subordinate IDs via `/etc/subuid`/`/etc/subgid` + `newuidmap`/`newgidmap` | any non-root UID/GID |
| Supplementary groups | Yuhaiin's own identity keeps Yuhaiin's groups; another UID/GID gets an empty list when Yuhaiin may call `setgroups` (see below) | replaced (empty) |
| Process containment | PID namespace; plus cgroup v2 when delegated or configured | PID namespace plus cgroup v2 (required) |

Set it with `"namespaceMode": "rootless"` or `"rootful"`. Saved inbounds
without the field use **rootless**; they keep working when Yuhaiin runs as
root, because a root-owned Yuhaiin can map the configured UID/GID into the
user namespace. Select `rootful` only when you need its behaviour and run
Yuhaiin as root. Neither mode ever falls back to the host network.

## How a session is built

Every SSH transport (TCP connection) that starts its first shell, exec or
SFTP channel gets one *session*:

1. Yuhaiin re-executes its own binary as a **session helper**, cloned into new
   PID, network and mount namespaces (and, in rootless mode, a new user
   namespace first). The main Yuhaiin process never calls `setns` and never
   touches the host network namespace.
2. Rootless only: the parent writes the helper's `uid_map`/`gid_map` while
   the helper waits on its control socket, then tells it to continue. Each
   map line takes a **host** ID to the ID of Yuhaiin's namespace that stands
   for it: `1000 → 1000` for a Yuhaiin on the host, `1009 → 0` for a Yuhaiin
   started by `podman unshare` (see [Inherited user namespaces](#inherited-user-namespaces-podman)).
   IDs inside a session therefore always mean the same as on the host.
3. Inside its namespaces, using capabilities that exist only in its own user
   namespace (rootless) the helper: makes mount propagation private, bind
   mounts a session-only `/etc/resolv.conf` (following symlinks; a dangling
   `systemd-resolved` link is handled), mounts a `/proc` of the session PID
   namespace, brings up loopback, opens `/dev/net/tun`, creates the TUN with
   `TUNSETIFF`, sets MTU, IPv4/IPv6 addresses and default routes over
   netlink, and opens a `NETLINK_SOCK_DIAG` socket.
4. The TUN, the sock_diag socket and a network-namespace handle are passed
   to Yuhaiin over `SCM_RIGHTS`. Yuhaiin attaches the TUN to its lightweight
   stack and uses the sock_diag socket for process lookup.
5. The helper clears every capability set, the bounding set and the ambient
   set, locks securebits, sets `no_new_privs`, and `execve`s into the
   **supervisor**. The supervisor is PID 1 of the session PID namespace, has
   no capabilities (verified from `/proc/self/status` before it reports
   ready), is non-dumpable, starts commands, forwards signals and reaps
   every process, including orphans.

Nothing in this sequence changes host interfaces, routes, rules, firewall or
`/etc/resolv.conf`. A failure at any step fails the session with a
classified error; no command starts.

## Requirements

Rootless:

- Linux 5.x or newer with user, network, mount and PID namespaces
  (`CONFIG_USER_NS`, `CONFIG_NET_NS`, `CONFIG_PID_NS`).
- Unprivileged user namespaces enabled: `user.max_user_namespaces > 0`, and
  where present `kernel.unprivileged_userns_clone=1`. On Ubuntu 23.10+,
  `kernel.apparmor_restrict_unprivileged_userns=1` denies them unless an
  AppArmor profile allows Yuhaiin (or the restriction is lifted).
  Granting a profile needs root, for example `/etc/apparmor.d/yuhaiin`:

  ```
  abi <abi/4.0>,
  include <tunables/global>
  profile yuhaiin /usr/local/bin/yuhaiin flags=(unconfined) {
    userns,
  }
  ```

  followed by `sudo apparmor_parser -r /etc/apparmor.d/yuhaiin`. Without
  root on such a host the SSH inbound cannot be used (rootful mode needs
  root too); Yuhaiin reports this restriction at inbound start.
- `/dev/net/tun` as a character device accessible to the Yuhaiin user (the
  kernel default is mode `0666`).
- A `/proc` that may be remounted inside a user namespace (not the case in
  some containers that mask parts of `/proc`).

Rootful: root, `/dev/net/tun`, and a writable cgroup v2 hierarchy.

Both: an authorized SSH public key and `allowUnsafeShell: true`.

At inbound start Yuhaiin creates one throw-away session (about 6 ms). If the
host cannot create sessions, the inbound does not start and reports why,
for example:

- `User Namespace is disabled: user.max_user_namespaces is 0 …`
- `/dev/net/tun does not exist; load the tun kernel module …`
- `/dev/net/tun is not accessible to the Yuhaiin user …`
- `UID mapping failed: rootless mode can run the session as the Yuhaiin user (UID 1000) only …`
- `UID mapping failed: host UID 1010 is not mapped into the user namespace Yuhaiin runs in, which maps only host UIDs 1009, 689824-755359`
- `GID mapping failed: …`
- `PID Namespace initialization failed: …`
- `Rootful mode requires root privileges …`

## UID, GID and groups

`uid` and `gid` are **host IDs** (IDs of the initial user namespace, as in
the host's `/etc/passwd`), in both modes and wherever Yuhaiin runs. In
rootless mode they default to Yuhaiin's own account (leave them at
`0`/empty). Other values work only when:

- Yuhaiin runs as host root (it may map any ID), or as root of an inherited
  user namespace, where it may map the host IDs that namespace covers (for
  Podman: the user's own ID and its `/etc/subuid` range); supplementary
  groups are then replaced by an empty list, or
- Yuhaiin runs on the host, `/etc/subuid`/`/etc/subgid` delegate the ID to
  the Yuhaiin user and `newuidmap`/`newgidmap` are installed. These tools
  are optional and only used in this case.

Otherwise the inbound refuses to start with a UID/GID mapping error naming
the IDs that can be mapped; it never pretends to switch users and never
substitutes another ID. In rootless mode you cannot switch to arbitrary host
accounts. The editor shows the detected usable IDs and rejects others before
saving.

The default identity **keeps the supplementary groups of the Yuhaiin
process**: `setgroups(2)` is denied inside the session, so the kernel keeps
every group unchanged. Groups that Yuhaiin's namespace does not map (for
Podman, for example host group `users`) appear as `nogroup` (65534) inside
the session but still grant their host access; this was verified with a
group-only directory. Rootless sessions cannot add groups the Yuhaiin process
does not have. Run Yuhaiin under a dedicated account without extra groups.

The shell runs with UID/GID equal to their host values, so file permissions
are exactly those of that host account, and file ownership on the host is
never changed. Root (UID 0) does not exist inside a
rootless session; setuid-root programs such as `sudo` and file capabilities
(for example on `ping`) have no effect, in both modes, because of
`no_new_privs` and the empty bounding set.

## Inherited user namespaces (Podman)

Yuhaiin can be started inside a user namespace another program created, for
example `podman unshare yuhaiin …` or a rootless container. Yuhaiin then runs
as root *of that namespace*, which is not host root. For host user
`example-user` (1009:1009) with `/etc/subuid` `example-user:689824:65536`:

```
Yuhaiin (podman unshare)  uid_map  0 1009 1        SSH session  uid_map  1009 0 1
                                   1 689824 65536
```

The session process is UID 1009 inside, which is UID 0 of Yuhaiin's
namespace, which is host UID 1009. `ls -l ~` in the shell shows
`example-user example-user`, and `cd ~; touch f; cat f; rm f` works exactly
as on the host. (Mapping the IDs one-to-one, `1009 1009 1`, would make the
shell host UID 690832 and show the home directory as `nobody:nogroup` with
`Permission denied`.)

Yuhaiin detects this automatically; no setting is needed:

- `/proc/self/uid_map` only describes the parent namespace, so Yuhaiin
  measures how deeply it is nested (the kernel allows 32 levels below the
  host; a short chain of helper processes counts the remaining ones). At
  depth 1, the parent is the host and IDs translate exactly.
- When Yuhaiin is nested deeper, or the depth cannot be measured, host IDs
  cannot be verified: automatically, sessions then use only Yuhaiin's own
  identity, shown with the IDs of its namespace, and explicit `uid`/`gid`
  values are refused unless a manual parent mapping is set (below).
- Mapping UID 0 of Yuhaiin's namespace needs `CAP_SETFCAP` there (Linux
  5.12+), which namespace root normally holds.
- Namespace root cannot write the host cgroup hierarchy, so Yuhaiin uses a
  delegated cgroup if present and otherwise the PID namespace supervisor.
- Rootful mode needs host root and is reported as unavailable.

### Manual parent namespace mapping

Deeper nesting is an implementation limit, not a kernel one: writing a
session map needs only IDs of Yuhaiin's own namespace (the session's
immediate parent), and the kernel checks those itself. What a nested process
cannot do is see what they are on the host. For such cases the advanced,
rootless-only `parentNamespaceUID`/`parentNamespaceGID` settings state the
pairing directly:

```json
"uid": 1009, "gid": 1009,
"parentNamespaceUID": 0, "parentNamespaceGID": 0
```

gives the session maps `1009 0 1` / `1009 0 1`. For example, Yuhaiin under
`podman unshare unshare --user --map-root-user` (depth 2) runs as UID 0 of a
namespace whose UID 0 is Podman's UID 0, i.e. host 1009.

- `uid`/`gid` stay the SSH target identity; the override never replaces
  them, and they must be set explicitly when it is used.
- The override names IDs of **Yuhaiin's namespace, not host IDs**. They must
  exist in Yuhaiin's `uid_map`/`gid_map` and pass the kernel rules: Yuhaiin's
  own IDs always, others only with `CAP_SETUID`/`CAP_SETGID`; mapping its UID
  0 needs `CAP_SETFCAP`; another GID needs a namespace that allows
  `setgroups`. Nothing is bypassed; the kernel rejects anything else.
- Where host IDs are resolvable (host, or one level like Podman), an
  override must agree with the automatic mapping, so it cannot make a shell
  show one host account while acting as another.
- Every rootless session reads its own `/proc/self/uid_map`, `gid_map` and
  IDs after switching to them, and the inbound refuses to start (each new
  session fails) unless they equal the plan.
- Yuhaiin cannot verify which host account the parent IDs stand for: the
  override asserts it. File access is still limited to what Yuhaiin's own
  namespace can do. Rootful mode refuses the setting.

The editor shows each session map line as *Automatic* or *Manual* and
rejects parent IDs that Yuhaiin's namespace cannot map.

## Detected environment

The inbound capabilities endpoint (`GET /api/v2/inbounds/capabilities`)
reports `ssh.environment`: where Yuhaiin runs (`host`/`inherited`, nesting
depth, its UID/GID maps and `setgroups` state), its host and namespace
identity and supplementary groups, the host UID/GID ranges a rootless inbound
may use and the namespace IDs a manual parent mapping may name, its
capabilities, and the kernel-verified identity of a throw-away
probe session (session UID/GID, its maps, whether groups are inherited and
whether the filesystem identity is preserved), plus the status of the user,
network, mount and PID namespaces, ID mapping, TUN, IPv4/IPv6, the
supervisor, cgroup v2 delegation and rootful mode. Values that could not be
determined are reported as `unknown` or omitted, never as 0. The probe
creates only its own namespaces, is shared by concurrent requests and cached
for 30 seconds. `ssh.serviceUID`/`serviceGID` are host IDs, and `ssh.root`
means host root.

The SSH inbound editor shows this result and highlights only problems; the
maps are under *Advanced details*.

## Host loopback forwarding

Optional and **off by default**. Selected loopback ports of every SSH session
reach loopback services of the network namespace Yuhaiin runs in (a host
PostgreSQL on `127.0.0.1:5432`, Redis on `127.0.0.1:6379`, an HTTP service
on `[::1]:8080`). Programs in the session keep connecting to `127.0.0.1` /
`::1` / `localhost`: no client setting, proxy variable, `/etc/hosts` entry or
user-started proxy is involved, and nothing changes on the host.

```json
"hostLoopback": {
  "enabled": true,
  "mappings": [
    { "protocol": "tcp", "sessionAddress": "127.0.0.1", "sessionPort": 5432, "hostAddress": "127.0.0.1", "hostPort": 5432 },
    { "protocol": "tcp", "sessionAddress": "::1",       "sessionPort": 5432, "hostAddress": "::1",       "hostPort": 5432 },
    { "protocol": "tcp", "sessionAddress": "::1",       "sessionPort": 8080, "hostAddress": "127.0.0.1", "hostPort": 18080 },
    { "protocol": "udp", "sessionAddress": "127.0.0.1", "sessionPort": 5353, "hostAddress": "127.0.0.1", "hostPort": 5353 }
  ]
}
```

| Field | Meaning |
|---|---|
| `protocol` | `tcp` or `udp` |
| `sessionAddress` | `127.0.0.1` or `::1` inside the session (explicit IPs; `localhost` is not accepted) |
| `sessionPort` | 1–65535, the port session programs connect to |
| `hostAddress` | a loopback IP of Yuhaiin's namespace: `127.0.0.0/8` or `::1` |
| `hostPort` | 1–65535, may differ from `sessionPort` |

Validation runs on save, also while forwarding is disabled. It rejects:

- non-loopback, unspecified (`0.0.0.0`, `::`) and IPv4-mapped addresses;
- zones and invalid IPs;
- ports outside 1–65535 and protocols other than `tcp`/`udp`;
- duplicate `protocol`+`sessionAddress`+`sessionPort`;
- more than 64 mappings;
- enabling forwarding without mappings.

LAN or external targets are not possible.

**IPv4 and IPv6 are separate.** `localhost` usually resolves to both `::1`
and `127.0.0.1`, and clients differ in which one they try first. Add both
mappings (the editor's *Add IPv4 and IPv6 for this port*) when clients use
`localhost`. The families may cross: `[::1]:8080` can forward to
`127.0.0.1:8080`. A family that is not mapped is never redirected to the
other one; it is the session's own loopback, so a client that tries `::1`
first gets "connection refused" there and then falls back to `127.0.0.1` by
its own logic.

### How it works

```text
session process ── connect(127.0.0.1:5432) ──▶ socket bound at 127.0.0.1:5432
                                                 (created by the session helper
                                                  inside the session netns, held
                                                  by Yuhaiin)
                                                        │ accept()
                                                        ▼
                                   Yuhaiin, in its own network namespace:
                                   dial tcp4 127.0.0.1:5432 ──▶ host PostgreSQL
```

1. For each mapping, the session helper binds a socket at exactly the
   session address and port (a listening TCP socket, or a bound UDP socket)
   inside the session network namespace. It does this after `lo` is up and
   before any command runs, and hands the socket to Yuhaiin over
   `SCM_RIGHTS`, like the TUN. A socket belongs to the namespace it was
   created in wherever its descriptor goes, so Yuhaiin accepts and reads on
   it without `setns` and without touching any OS thread's namespace.
2. Yuhaiin opens the host side with an explicit family (`tcp4`/`tcp6`,
   `udp4`/`udp6`) in its own namespace and relays. Forwarded flows bypass
   routing: no rule can send them to an outbound, and they never pass the
   session TUN or the packet stack, so they cannot loop back into a session.
3. TCP uses the stream relay of normal inbounds: EOF, half-close, reset,
   cancellation and session teardown behave the same, with up to 1024
   concurrent connections per session.
4. UDP keeps datagram boundaries. Each session source gets a host socket,
   up to 256 flows per session. Replies are accepted only from the mapped
   host endpoint and are sent back from the session address the program
   used. A flow closes after 60 seconds without traffic.
5. Each forwarded flow appears in Connections and the traffic statistics
   with component `ssh-host-loopback` and node `host loopback`. It carries
   the SSH inbound ID and the session process (resolved through the
   session's sock_diag socket). Failures are logged at most once per
   mapping every 10 seconds; per-connection and per-flow events are debug
   logs.

The endpoints belong to each session: separate SSH transports have separate
sockets, and closing a session closes all its sockets, connections and flows.
A mapped session port is in use inside the session (programs there cannot
bind it); unmapped ports stay the session's own loopback. Changes apply to
new SSH connections; open ones keep the mappings they started with.

Why not NAT: an nftables `output` DNAT of `127.0.0.1` to the gateway does
reach the TUN, but replies only return for IPv4, and only with
`route_localnet`. For IPv6 the kernel drops the de-NATed reply whose
destination becomes `::1` on a non-loopback device (`Ip6InAddrErrors`, no
`route_localnet` equivalent). This was measured on Linux 7.2. Sockets in the
session namespace serve both families the same way, so no nftables rule,
sysctl or route exists anywhere, and the host's nftables and routing tables
are never touched.

### Requirements, runtime status and failures

- **Platform:** the Linux SSH inbound, rootless or rootful, including Yuhaiin
  started by `podman unshare`. No nftables or extra capability is needed.
  Ports below 1024 work: the session helper briefly holds
  `CAP_NET_BIND_SERVICE` in its own user namespace.
- **Runtime check:** the capabilities endpoint reports
  `ssh.environment.features.hostLoopbackIPv4` / `hostLoopbackIPv6` (with
  `hostLoopbackError`) from a throw-away session that reserves `127.0.0.1:1`
  and `[::1]:1`. IPv6 fails when IPv6 is disabled in the kernel. The editor
  shows this next to the setting, separately from whether it saves.
- **Failures:** a mapping that cannot be reserved makes the inbound fail to
  start (its runtime status shows why). A host service that is not
  listening makes only that connection fail (connection refused, or a closed
  connection after the dial timeout); nothing is retried on another family.

### Security

Every user of the SSH inbound can reach the mapped host services, with the
host service's own authentication. Map only what SSH users should use.
Host targets are restricted to loopback addresses and to the configured
ports. SSH authentication is unchanged. Nothing in the host's firewall,
routes or interfaces changes, and no namespace privilege is added to
session processes.

## Process containment and cleanup

- **PID namespace (always).** Every session process lives in the session PID
  namespace. Closing the session kills PID 1; the kernel then kills every
  remaining process of the namespace, including background jobs, `setsid`,
  `nohup` and double-forked daemons, before Yuhaiin sees PID 1 exit.
  Processes cannot leave a PID namespace.
- **cgroup v2 (when available).** If `cgroupRoot` is set, it must be a
  writable cgroup v2 directory and is used (startup fails otherwise). In
  rootful mode, `/sys/fs/cgroup/yuhaiin/ssh/<inbound-hash>` is required as
  before. In rootless mode Yuhaiin uses that path when it runs as root, or a
  subtree of its own cgroup when systemd delegated it (`Delegate=yes`, which
  marks the cgroup with the `trusted.delegate`/`user.delegate` attribute).
  Without delegation the hierarchy belongs to the service manager and is not
  modified; the PID namespace supervisor alone is used. With a cgroup, the
  helper is placed into the session cgroup atomically (`CLONE_INTO_CGROUP`),
  `cgroup.kill` ends the tree, and a restarted Yuhaiin reaps sessions left by
  a crash.
- **Yuhaiin crash.** If Yuhaiin is killed, the kernel closes its end of the
  control socket; the supervisor sees EOF and exits, which ends the session.
- **Supervisor crash.** If the supervisor is killed, its commands die with the
  namespace, running channels report exit status 255, and the next command on
  that transport gets a fresh session.

For a systemd user service, `Delegate=yes` enables cgroup containment:

```ini
[Service]
ExecStart=/usr/local/bin/yuhaiin
Delegate=yes
```

## Inbound configuration

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
      "namespaceMode": "rootless",
      "username": "alice",
      "authorizedKey": "ssh-ed25519 AAAA... alice@host",
      "shell": "/bin/bash",
      "timezone": "Asia/Tokyo",
      "sftpReadOnlyPaths": ["/srv/archive", "/srv/backups"],
      "mtu": 1500,
      "ipv6": true,
      "maxSessions": 8,
      "allowUnsafeShell": true
    }
  }
}
```

`uid`/`gid` are omitted (0) above, so the shell runs as Yuhaiin's own
account. A rootful inbound adds `"namespaceMode": "rootful"` and explicit
`"uid"`/`"gid"` (host IDs). The server generates an Ed25519 host key on the first save
and preserves it across edits and restarts; a supplied `hostKey` overrides
it. Keep host private keys out of logs and exports. Use a restricted
listening address or a firewall.

## Session addressing, DNS and FakeIP

The default IPv4 gateway and session address are `172.31.254.1` and
`172.31.254.2/30`; the IPv6 pair is `fd42:7d2a:9b31::1` and
`fd42:7d2a:9b31::2/64`, outside the default FakeIP and Tailscale ranges.
Inbound startup rejects overlap with the active FakeIP pools, and an update
that introduces an overlap closes the inbound. `gatewayIPv4`, `sessionIPv4`,
`gatewayIPv6` and `sessionIPv6` can be overridden.

The session resolver lists the IPv4 gateway and, with IPv6 enabled, the IPv6
gateway. DNS over UDP and TCP to either gateway is answered by Yuhaiin's DNS
handling, so FakeIP answers and the routing rules apply. The resolver file
exists only in the session's mount namespace and disappears with it.

## Sharing rules

- All channels of one SSH transport (shell, exec, SFTP) share one session:
  loopback, ports, resolver and PID namespace.
- Separate SSH transports never share a session, even with the same key.
- Each command holds a lease; the last lease to end closes the session (TUN,
  stack, namespaces, processes). A later command on the same transport
  creates a new session.
- Disconnecting the transport ends its session and every process in it.
- A command's own process group is killed when its channel closes; other
  background processes of the session live until the session ends.

## Process lookup

Routed flows carry a process scope backed by the session's sock_diag socket.
Socket queries see only the session's sockets; the owner is then resolved
in host `/proc` and must be a member of the session network namespace, so
host processes are never reported. sock_diag reports the owner in the
session's user namespace; it is translated through the session map before
matching `/proc` owners, which Yuhaiin sees in its own namespace. The PID is
the PID in Yuhaiin's PID namespace and the UID is the host UID.

## Security

Preserved from the previous version: public-key authentication only;
password authentication, `direct-tcpip`, agent forwarding and remote
listening are disabled; `allowUnsafeShell` must be acknowledged; SFTP
read-only path rules; persistent host keys; `maxSessions`.

Added by this design:

- Shell, exec and SFTP processes run with no capabilities, an empty bounding
  set, locked securebits and `no_new_privs`, in both modes.
- In rootless mode setup capabilities exist only inside the session's user
  namespace, which has no authority over the host network namespace. The only
  way out of the session network is the TUN.
- The session `/proc` shows only session processes, so same-user host
  processes, including Yuhaiin itself, cannot be inspected or ptraced through
  `/proc` or PIDs from inside a session. The setup helper and supervisor are
  non-dumpable.
- Abstract Unix sockets are per network namespace and therefore isolated.

Not isolated, by design of this feature:

- **The filesystem is the host filesystem.** There is no filesystem sandbox.
- Filesystem Unix-domain sockets (for example a D-Bus or Docker socket) are
  reachable with the shell account's permissions.
- **In rootless mode the shell normally runs as the Yuhaiin account itself.**
  It can read and modify everything that account can, including Yuhaiin's
  configuration directory, database and secrets, and files owned by it.
  Run Yuhaiin under a dedicated account, or as root with a separate `uid`, if
  SSH users must not be able to read Yuhaiin's data.

## Behaviour notes

- Supports SSH `session` channels with `shell`, `exec`, the `sftp` subsystem,
  PTY allocation, terminal resize and `signal` requests.
- `HOME`, `USER`, `LOGNAME` and the working directory follow the local
  account of the shell UID; a missing home falls back to `/`. An empty
  `shell` selects the account's login shell, with `/bin/sh` as fallback.
- `timezone` sets `TZ` for session processes only.
- SFTP re-executes the Yuhaiin binary inside the session; `sftpReadOnlyPaths`
  are SFTP path rules, not filesystem permissions.

## Validation

All integration tests run as a normal user. They skip only when this host
cannot create rootless sessions and print why; set `YUH_REQUIRE_ROOTLESS=1`
to make that a failure (CI does).

```sh
go test -race -count=1 ./pkg/net/proxy/sshserver ./pkg/net/netlink ./pkg/inbound
YUH_REQUIRE_ROOTLESS=1 go test -count=1 -v ./pkg/net/proxy/sshserver
```

Inside Podman, the shell identity and host file access are checked with:

```sh
go test -c -o /tmp/ssh.test ./pkg/net/proxy/sshserver
podman unshare env YUH_SSH_SERVER_INTEGRATION=1 YUH_SSH_TEST_HOME=$HOME \
    YUH_SSH_TEST_UID=$(id -u) YUH_SSH_TEST_GID=$(id -g) /tmp/ssh.test -test.v
```

They cover authentication and forwarding policy, shell/exec/PTY/SFTP,
IPv4/IPv6 TCP and UDP, DNS over UDP/TCP through both gateways, FakeIP
addresses, process lookup per transport, sharing within and isolation
between transports, host network invariants, disconnect variants with
detached process trees, supervisor and Yuhaiin crashes, signal forwarding,
the rootless privilege proof and preflight errors.

To exercise cgroup v2 containment, run inside a delegated scope:

```sh
go test -c -o /tmp/ssh.test ./pkg/net/proxy/sshserver
systemd-run --user --scope -p Delegate=yes sh -c \
  'YUH_SSH_SERVER_CGROUP_ROOT=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup) /tmp/ssh.test -test.v'
```

Rootful mode (as root): `sudo YUH_SSH_SERVER_INTEGRATION=1 YUH_SSH_SERVER_MODE=rootful YUH_SSH_SERVER_CGROUP_ROOT=… /tmp/ssh.test -test.v`.

Benchmarks:

```sh
go test -run '^$' -bench 'SSHServer' -benchtime=100x ./pkg/net/proxy/sshserver
```

Failure handling (user namespaces disabled, missing or inaccessible TUN,
rejected UID/GID maps, missing PID or network namespaces, cancellation,
read-only cgroups) and rootless-versus-rootful setup cost are tested in
[sessionnet](https://github.com/yuhaiin/sessionnet).
