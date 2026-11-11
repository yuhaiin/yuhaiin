# Direct peer tunnels

Use a Peer Tunnel outbound to reach TCP and UDP services on another Yuhaiin
instance's LAN. A Peer Discovery inbound exchanges public UDP endpoints for
the pair. The two peers send WireGuard traffic directly using those endpoints.

## Set up a pair

1. On a publicly reachable Yuhaiin instance, add an enabled **Peer Discovery**
   inbound with a UDP listener such as `:51821`. Allow that UDP port through
   the server firewall. Generate one pairing token and copy it to both peers.
2. On the LAN side, add an enabled **Peer Tunnel Publisher** inbound. Set the
   discovery server to its public `host:port` and paste the pairing token.
3. On the calling side, add a **Peer Tunnel** outbound with the same discovery
   server and token. Use it as the first step in the outbound chain.
4. Generate a WireGuard key pair on each side. Put each side's public key into
   the other side's **Peer public key** field. Keep each private key local.
   The Web UI can generate keys with Web Crypto X25519 in a secure context.
   With WireGuard tools installed, `wg genkey` generates a private key and
   `wg pubkey` reads the private key from standard input.
5. Use distinct tunnel IPs that do not overlap the LAN routes. The defaults are
   `10.88.1.1` on the publisher and `10.88.1.2` on the outbound. Each
   side's **Peer tunnel IP** is the other side's **Local tunnel IP**.
6. Set the **LAN routes** on both sides to the destination CIDRs you want to
   reach, for example `192.168.1.50/32`. On the caller, add a routing rule
   sending these destinations to the Peer Tunnel node. On the LAN side, the
   publisher uses the existing inbound access and routing policies. Use a
   direct route there to reach the target LAN. Then connect to the service's
   LAN IP and port through a calling-side inbound such as Mixed or TUN.

Use a different random token and publisher inbound for each pair. The discovery
inbound accepts a list of pairing tokens on one UDP port. The tunnel IPs and LAN
routes must use one address family per pair. The outer UDP socket follows the
discovery server's address family.

## Connectivity

Both peers must be able to send UDP to the discovery server and to each other.
The publisher keeps its registration open while enabled. The outbound starts
discovery on demand. NATs that assign a different public mapping per destination
can prevent a direct connection. Peers behind the same NAT may require NAT
hairpinning. A successful tunnel can keep carrying traffic during a discovery
server outage while the learned UDP endpoints remain valid.

## Tests and benchmarks

```sh
go test -race ./pkg/net/peerrendezvous ./pkg/inbound -run 'Test(Rendezvous|SocketPunch|PeerTunnel)'
go test ./pkg/net/peerrendezvous ./pkg/inbound -run '^$' -bench 'Benchmark(CoordinatorRegistration|PeerTunnelTCP)' -benchmem -count=3
```

The TCP benchmark measures an established loopback connection with 32 KiB echoed
per iteration. Reported bytes include both directions. The registration
benchmark exercises the coordinator's protocol handler in memory.
