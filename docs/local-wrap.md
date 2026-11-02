# Local CLI network namespace wrap

`yuhaiin wrap` runs a local program in an isolated Linux network namespace.
Its TCP, UDP and DNS traffic enters the running Yuhaiin service's normal inbound
routing and policy pipeline. Children inherit the same network. Separate wrap
invocations have independent loopback networks and ports.

## Enable the local service

Start Yuhaiin with an absolute Unix socket path and a trusted non-root Unix
account. For example, for an account with UID/GID 1000:

```sh
sudo yuhaiin run -path /var/lib/yuhaiin \
  -wrap-socket /run/yuhaiin/wrap.sock -wrap-uid 1000 -wrap-gid 1000
```

The supervisor requires namespace, mount, TUN and credential-changing privileges
and `/dev/net/tun`. It also requires a writable, dedicated cgroup v2 subtree with
`clone3(CLONE_INTO_CGROUP)` and `cgroup.kill` support. Root is a straightforward
way to provide these permissions. With systemd, configure an appropriate
`Delegate=yes` subtree and use `-wrap-cgroup-root` if the default is not writable.
The default is `/sys/fs/cgroup/yuhaiin/wrap/<socket-path-hash>`; keep the root
stable across restarts so abandoned sessions can be recovered and killed.

The socket's direct parent must be service-owned and not writable by other
users. Newly created parent directories use mode 0755. The socket uses mode
0600 and belongs to the configured UID/GID. Existing parent directories must
also allow that account to traverse the path. Existing regular files and live
listeners are preserved; an owned stale socket can be replaced after a crash.

Only the configured UID can launch commands. The service obtains the client's
actual UID, primary GID and supplementary groups from the kernel. The target
runs without the service's root identity. This interface is for trusted local
users and is disabled unless `-wrap-socket` is supplied.

## Run programs

As the permitted account:

```sh
yuhaiin wrap -- curl https://example.com
yuhaiin wrap -- bash
yuhaiin wrap -- ./my-program 'an argument with spaces'
yuhaiin wrap -- sh -c 'producer | consumer'
yuhaiin wrap -socket /custom/path/wrap.sock -- my-program
```

Arguments after `--` are passed as argv, including empty arguments. Only an
explicit shell invocation interprets pipelines, substitutions or redirections.
The current directory and environment come from the CLI. Standard input,
output and error remain separate for pipes and redirections. When both stdin
and stdout are terminals, the CLI automatically allocates a PTY, copies its
window size, forwards resize events and restores the original terminal state.
Use `-no-tty` to disable automatic terminal allocation.

The program's parent is the local Yuhaiin service. The CLI stays attached for
session lifetime, terminal handling and status reporting. Normal exit codes
are preserved; signal exits use `128 + signal`. Missing executables return 127;
setup and protocol failures return 125. SIGINT, SIGTERM, SIGHUP and SIGQUIT
received by the CLI are forwarded to the command. Terminal-generated job
control operates through the PTY.

When the command exits or the client disconnects, the service kills remaining
session descendants and releases the namespace and packet stack. Detached
background processes do not outlive the wrap invocation. Eight concurrent
sessions are allowed. Startup failures reject the command before its gate is
released. Service shutdown terminates active sessions; a subsequent startup
cleans processes left by a previous crash.

## Routing and compatibility

Routing continues to follow existing rules; a namespace does not force all
traffic to one proxy node. IPv6 follows the service's IPv6 setting at startup.
DNS uses a private resolver and NSS hosts configuration, including masking
conventional nscd directories, without changing the host's files. Other NSS
account databases are preserved. An existing `/etc/nsswitch.conf` is required.
Custom host resolver services and arbitrary pathname Unix sockets are outside
this isolation boundary.

`127.0.0.1` and `::1` refer to the wrapped network. Inherited proxy variables
pointing to a host loopback listener may therefore fail. Programs that delegate
to an existing desktop instance or host service need separate compatibility
checks. The host filesystem, processes, setuid executables and inherited stdio
FDs are not a general security sandbox. Service filesystem restrictions must
allow access to the caller's executable, working directory and required files.

The web UI now exposes **Settings → Local wrap** defaults for the service
socket, authorized non-root UID/GID, cgroup root, maximum sessions and an optional IANA time zone. These
values are stored in the server settings database, and applied only when the
daemon restarts. Saving the form does **not** start or stop a running socket.
The option is opt-in and disabled on existing installations. The UI is not a
sandbox boundary: only a trusted administrator should enable process launching.

Explicit `-wrap-socket`, `-wrap-uid`, `-wrap-gid`, `-wrap-cgroup-root` and
`-wrap-max-sessions` and `-wrap-timezone` flags override the corresponding saved values at startup.
An explicitly empty `-wrap-socket=` disables a saved enabled configuration.
If `timezone` is configured (for example `Asia/Tokyo`), each launched
wrap command and its descendants receive `TZ=Asia/Tokyo`, replacing any
inherited `TZ` variable. When unset, the caller's original environment is
preserved. This changes local time formatting, not the kernel clock or host
process environment. Install IANA zoneinfo data (usually `tzdata`) to support
regional time zones and daylight saving transitions.

Run `yuhaiin wrap -socket /your/socket.sock -- <program> [args...]` when using
a nondefault socket path. See [the design notes](research-cli-netns-wrap.md)
for sources and alternatives.

## Validation and benchmarks

```sh
go test -race -count=1 ./pkg/net/proxy/localwrap ./pkg/net/proxy/processnet ./pkg/net/proxy/sshserver ./pkg/inbound ./cmd/yuhaiin
go test -run '^$' -bench 'Benchmark(LaunchProtocol|LocalCommand)$' -benchmem -count=3 ./pkg/net/proxy/localwrap
```

Privileged integration exercises real client credential dropping, namespace
inheritance, IPv4/IPv6 TCP and UDP, namespace-scoped process lookup, DNS over
UDP/TCP, libc `getent`, signal forwarding, detached descendants and shutdown:

```sh
go test -c -o /tmp/yuhaiin-wrap.test ./pkg/net/proxy/localwrap
sudo mkdir -p /sys/fs/cgroup/yuhaiin-wrap-test
sudo YUH_WRAP_INTEGRATION=1 YUH_WRAP_CGROUP_ROOT=/sys/fs/cgroup/yuhaiin-wrap-test \
  /tmp/yuhaiin-wrap.test -test.v -test.timeout=120s -test.run '^TestLocalWrap.*Integration$'
sudo rmdir /sys/fs/cgroup/yuhaiin-wrap-test
```

A disposable user namespace can qualify networking without the production
cgroup manager. This test-only constructor is not a production fallback:

```sh
unshare --user --map-auto --map-root-user --mount --net sh -c '
  ip link set lo up && YUH_WRAP_NAMESPACE_TEST=1 /tmp/yuhaiin-wrap.test \
    -test.v -test.timeout=120s -test.run "^TestLocalWrap.*Integration$"
'
```

`BenchmarkLaunchProtocol` measures Unix descriptor passing and request/status
framing. `BenchmarkLocalCommand` adds an ordinary `/bin/true` subprocess with
an injected non-isolating test launcher; it excludes namespaces and routing.
`BenchmarkIsolatedCommand` includes a fresh CLI helper, real namespace setup,
DNS isolation, TUN packet stack and cleanup. Enable either integration mode
above and run the test binary with `-test.run '^$' -test.bench
'^BenchmarkIsolatedCommand$' -test.benchmem -test.count=3`. These are startup
and lifecycle measurements, not network throughput.

On Go 1.27.3, Linux amd64 and AMD Ryzen 5 5600G, the median of three
one-second runs was:

| Benchmark | Time/op | B/op | Allocs/op |
| --- | ---: | ---: | ---: |
| Launch protocol | 24.064 us | 1,795 | 37 |
| Local command, without namespace | 560.244 us | 43,235 | 154 |
| Isolated command lifecycle, disposable user namespace | 41.970 ms | 167,693 | 646 |

The isolated measurement uses the test-only unmanaged constructor and excludes
production cgroup creation/reaping costs. Raw output is in
[local-wrap-2026-11-02.txt](benchmarks/local-wrap-2026-11-02.txt).
