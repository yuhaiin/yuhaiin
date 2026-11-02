# Local network namespace wrap: implementation notes

Research date: 2026-11-02. Initial source baseline: `main` at `a4f33647`,
with `github.com/yuhaiin/sessionnet` at `efac23438c74`.

Local command wrapping reuses the SSH inbound's namespace/TUN networking.
The implementation adds a local Unix socket control endpoint and CLI while
keeping packet processing in the running Yuhaiin service. See
[Local CLI wrap](local-wrap.md) for configuration and validation commands.

## Design decisions

- Each invocation owns a private network and mount namespace. Descendants
  inherit them. A wrapped shell can run several programs in the same network.
- The service starts the command using the connecting Unix account's kernel
  credentials, including supplementary groups. The request cannot select a UID.
- The CLI sends argv, environment, working directory and descriptors. Commands
  are not reconstructed as shell strings. The service is the actual parent.
- A client-allocated PTY handles interactive terminal input, window changes and
  job control. Non-terminal launches pass three stdio descriptors directly.
- Cgroup v2 containment is mandatory in production. Startup acquires the stable
  cgroup manager and cleans orphaned sessions before accepting local launches.
- Namespace/TUN setup and inbound routing must succeed before the startup gate
  releases the command. Errors never select the host network as a fallback.
- The packet adapter is shared with SSH through `processnet.Attach`, including
  namespace-scoped process lookup. FakeIP overlap checks follow runtime changes.

Source: [CLI](../cmd/yuhaiin/wrap.go),
[local service](../pkg/net/proxy/localwrap/server_linux.go),
[packet adapter](../pkg/net/proxy/processnet/network_linux.go),
[SSH integration](../pkg/net/proxy/sshserver/shared_linux.go).

## Kernel and runtime constraints

`setns` changes the calling thread. Network namespace entry requires
`CAP_SYS_ADMIN` in the caller and target owner user namespaces. Mount namespace
entry also involves `CAP_SYS_CHROOT` and restrictions on shared `CLONE_FS` state.
Go documents that an external command inherits inheritable OS thread state when
started from a goroutine locked to that thread. Sessionnet handles namespace
entry and restoration; callers should reuse that implementation.
Sources: [setns(2)](https://man7.org/linux/man-pages/man2/setns.2.html),
[Go os/exec](https://pkg.go.dev/os/exec#Cmd.Run).

Unix sockets provide kernel peer credentials and descriptor passing. Peer groups
are a binary `gid_t` array and must not be decoded as a C string.
Sources: [unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html),
[Linux SO_PEERGROUPS implementation](https://github.com/torvalds/linux/blob/master/net/core/sock.c).

Changing the network namespace alone does not replace resolver configuration.
`ip netns exec` similarly uses mount namespaces for configuration files.
Sources: [ip-netns(8)](https://man7.org/linux/man-pages/man8/ip-netns.8.html),
[sessionnet namespace setup](https://github.com/yuhaiin/sessionnet/blob/efac23438c74/namespace_linux.go).

`nss-resolve` communicates with the host resolver through a pathname Unix socket.
A private `resolv.conf` alone cannot cover this path. Wrap opts into sessionnet's
private `hosts: files dns` NSS configuration and masks conventional nscd runtime
directories while retaining other NSS databases.
Source: [systemd nss-resolve](https://www.freedesktop.org/software/systemd/man/latest/nss-resolve.html).

`cgroup.kill` kills the cgroup tree and handles concurrent forks. A supervisor
crash still requires orphan cleanup on restart; cgroup membership alone does not
cause automatic termination when the supervisor dies.
Source: [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html).

## Scope and alternatives

Network namespaces isolate routes, IP stacks, ports and abstract Unix sockets.
They do not isolate pathname Unix sockets, shared filesystems or existing socket
FDs. A program delegating work to an existing host application may therefore use
that application's network. Loopback addresses refer to the wrapped namespace,
so host-local proxy environment variables may need adjustment.
Sources: [network_namespaces(7)](https://man7.org/linux/man-pages/man7/network_namespaces.7.html),
[sessionnet configuration contract](https://github.com/yuhaiin/sessionnet/blob/efac23438c74/session.go).

A direct CLI-parent implementation would need a privileged helper and additional
namespace/TUN FD ownership protocols. Persistent named namespaces would add
shared-session authorization and lifetime management. Neither is required for
the initial local-service design. Desktop application compatibility remains
application-specific; this feature is not a filesystem or general security sandbox.
