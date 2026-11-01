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
- An authorized SSH public key. The server creates and persists an Ed25519\n  host key automatically when the SSH inbound is first saved.
- An explicit `allowUnsafeShell: true` acknowledging that filesystem and
  Unix-domain socket access is not isolated.

No networking CLI is executed. The dependency
[sessionnet](https://github.com/yuhaiin/sessionnet) configures the per-command
network namespace, resolver, TUN, routes and lifecycle through Netlink/syscalls.

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

Replace the sample authorized public key and account IDs. The server\ngenerates an Ed25519 host key on the first save and preserves it across\nsubsequent edits and restarts. A supplied `hostKey` overrides automatic\ngeneration. Keep SSH host private keys out of public logs and exports. Use a restricted listening address
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
- Each command receives a separate network namespace and TUN. The host routing
  table is not changed. IPv4/IPv6 and DNS queries are delivered to the same
  Yuhaiin inbound handler used by TUN and WireGuard listeners.
- The session must successfully create and connect its TUN and lightweight
  stack before a command can start. On failure, execution is rejected rather
  than falling back to ordinary host routing.
- Cancelling the SSH connection shuts down its session. The underlying
  sessionnet library currently kills the process group, not escaped daemonized
  descendants. Add cgroup v2 containment before relying on complete cleanup.
- This initial version has its own configured SSH public-key identity. It does
  **not** claim integration with the management user's credential and identity
  system. Setting the inbound `authentication` field is rejected.

## Validation

Run `go test ./pkg/net/proxy/sshserver ./pkg/contract/inbound ./pkg/inbound`.
A privileged end-to-end SSH/TUN/DNS integration job is still required before
promoting the feature from experimental status.
