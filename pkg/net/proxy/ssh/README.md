# SSH outbound (direct-tcpip)

Yuhaiin can connect to an SSH server and open TCP connections using SSH
`direct-tcpip` channels. Multiple connections share one authenticated SSH
transport. No system `ssh` executable, TUN device, or local SOCKS port is needed.

## Node configuration

In **Outbound → Add node**, choose the **SSH** template. Set the **simple**
step to the SSH server's host and port (typically 22), then configure the SSH
step's username and authentication. Example node chain:

```json
{
  "chain": [
    {"type": "simple", "simple": {"host": "ssh.example.org", "port": 22}},
    {"type": "ssh", "ssh": {
      "user": "alice",
      "password": "your-password",
      "host_key": "SHA256:REPLACE_WITH_THE_SERVER_FINGERPRINT",
      "keep_alive_seconds": 30
    }}
  ]
}
```

You can also paste the server's `ssh-ed25519 AAAA...` public key in `host_key`.
SSH **host key verification is mandatory**; connections fail closed if it is
missing or does not match. Obtain and verify the fingerprint through a trusted
channel, not solely through an unauthenticated `ssh-keyscan`.

A full public-key pin also selects its compatible host-key algorithm, including
RSA-SHA2 for RSA keys. A SHA256 fingerprint carries no algorithm information:
it must match the key selected by normal SSH negotiation. If a server offers
multiple host keys and a fingerprint selects the wrong one, use the full
trusted public key to select it explicitly.

Authentication accepts a password, a PEM/OpenSSH private key in `private_key`,
or both (private key attempted first). For encrypted private keys, set
`private_key_passphrase`. Passwords and key material are saved in the existing
node configuration store, so protect exports and backups. There is no
interactive password/2FA or SSH agent support in this implementation.

`keep_alive_seconds` is optional (0 disables SSH keep-alives). Invalid
negative values and values above 3600 are rejected. Existing SSH sessions
are recreated after disconnection; editing or removing the node closes
the session.

An unanswered keep-alive is allowed one keep-alive interval for its reply,
then the transport is closed. A negative reply still proves the server is
alive. Individual TCP channels support independent read/write deadlines;
timing out one channel does not close the shared SSH session.

## Limits

* **TCP only.** SSH `direct-tcpip` has no general UDP forwarding facility. UDP
  requests return an explicit error. Configure a separate UDP outbound or
  a network split for UDP instead.
* The SSH server must permit TCP forwarding (`AllowTcpForwarding yes` in
  OpenSSH) and must permit the desired destination (`PermitOpen`).
* Domain names are sent to the SSH server for resolution, which allows
  remote-only DNS names without leaking them to a local resolver.
* SSH provides encryption and authentication; its transport is TCP, so
  nested TCP traffic can suffer under packet loss.

See [validation and benchmarks](BENCHMARK.md) for test commands, local results,
and the channel deadline bridge's resource costs.
