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

## Behavior and limits

- Public-key authentication only. Password authentication, `direct-tcpip`
  port forwarding, SSH agent forwarding, and remote TCP listening are disabled.
- Supports SSH `session` channels with `shell`, `exec`, PTY allocation and
  terminal resize. No SFTP subsystem.
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
- Cancelling the SSH connection shuts down its session. The underlying
  sessionnet library currently kills the process group, not escaped daemonized
  descendants. Add cgroup v2 containment before relying on complete cleanup.
- This initial version has its own configured SSH public-key identity. It does
  **not** claim integration with the management user's credential and identity
  system. Setting the inbound `authentication` field is rejected.

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
