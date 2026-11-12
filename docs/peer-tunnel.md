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
discovery server's address family. When the server's hostname has both IPv6
and IPv4 addresses, the peers prefer IPv6. A peer that gets no answer over
IPv6, or whose partner registered over IPv4, switches to IPv4. Both peers must
share one family to connect. To force a family, enter an IP address or use a
hostname that resolves to that family only.

A Peer Tunnel must be the first step of an outbound chain. It opens its own UDP
socket and cannot run through an earlier step.

## Connectivity

Both peers must be able to send UDP to the discovery server and to each other.
The publisher keeps its registration open while enabled. The outbound starts
discovery on demand. NATs that assign a different public mapping per destination
can prevent a direct connection. Peers behind the same NAT may require NAT
hairpinning. A direct path remains usable briefly if discovery becomes
unreachable. Both peers stop forwarding when their last authorization expires,
about 20 seconds after the last successful refresh. After that, each peer
resolves the discovery server's hostname again every 20 seconds and follows it
to a new address. A peer also drops the direct path after the discovery server
reports its partner offline three times in a row, about 6 seconds. New
connections then fail at the outbound's 8-second wait for a direct path.

## View and manage peers

Open **Peer tunnels** on the calling-side Outbounds page. It lists publishers
for the enabled Peer Tunnel outbounds, including the observed UDP endpoint,
configured tunnel IP and LAN CIDRs. Online means the publisher has a live
registration. A direct UDP path is still required. The list refreshes while
open and querying it leaves existing tunnels alone.

On the discovery server, open the **Registered peer pairs** panel in the
Peer Discovery inbound. Each row represents one token and shows the client
and publisher endpoints. **Kick** drops both registrations and denies the pair
for 30 seconds. **Block** persists the denial across restarts. **Unblock**
allows both peers to register again. The peers stop forwarding when they
receive the denial on their next discovery exchange. If the denial cannot
reach them, their authorization expires as described above.

## Tests and benchmarks

```sh
go test -race ./pkg/net/peerrendezvous ./pkg/inbound ./pkg/node -run 'Test(Rendezvous|SocketPunch|Peer)'
go test ./pkg/net/peerrendezvous ./pkg/inbound -run '^$' -bench 'Benchmark(CoordinatorRegistration|CoordinatorLookup|PeerTunnelTCP)' -benchmem -count=3
```

The TCP benchmark measures an established loopback connection with 32 KiB echoed
per iteration. Reported bytes include both directions. The registration and lookup
benchmarks exercise the coordinator's protocol handler in memory.
