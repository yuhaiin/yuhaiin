# LAN Link

LAN Link lets a Yuhaiin outbound reach TCP and UDP services on another
Yuhaiin instance's LAN. The two instances exchange encrypted traffic directly
after a public UDP discovery inbound introduces them.

## Set up a gateway

1. On the public instance, create and enable a **Peer Discovery** inbound and
   allow its UDP port through the firewall. Generate a **Gateway registration
   key** and give it to the LAN gateway administrator.
2. On the LAN instance, create a **LAN Link gateway** inbound. Enter the
   allowed LAN CIDRs and configure the public discovery address and registration
   key under **Discovery setup**. Save the inbound.
3. For each client, select **Generate invitation** on the saved inbound. In the
   client's Outbounds, create a **LAN Link** outbound and paste the invitation.
   Use a separate invitation for each client. The gateway can revoke any one
   invitation from its client list.

The allowed LAN CIDRs may mix IPv4 and IPv6 networks. The tunnel is
dual-stack: the gateway keeps a random private IPv4 subnet (`subnet`, a /22)
and a random ULA IPv6 subnet (`subnet6`, a /64) that do not overlap the
allowed LAN CIDRs. You can override either with a unicast subnet that has
enough addresses. The gateway assigns its own address and a distinct address
per invitation in each subnet. The addresses survive restarts. Clients
reconnect automatically with their new assignments after a subnet change. A
gateway saved by an older version keeps its single subnet until the inbound is
saved again; an IPv6 network in `subnet` then moves to `subnet6`. A client
that predates dual-stack tunnels keeps working against a single-family
gateway, using the family of the first LAN CIDR.

Each instance generates and stores its own WireGuard private key. It uses the
invitation to authenticate the public key exchange and the gateway's address
assignment. The discovery server authenticates registrations with a separate
key. Keep invitations private.

A standalone LAN Link outbound automatically handles IP destinations in the
advertised LAN prefixes after explicit routing rules have been evaluated.
The most specific prefix wins. If two LAN Links advertise the same matching
prefix, add an explicit rule to choose the outbound. On the gateway, explicit
rules apply before the default direct path to the allowed LAN destinations.
A default block policy takes precedence over these automatic routes.

Both peers need working UDP paths to discovery and to each other. The NAT and
network constraints below also apply to LAN Link.

### Client-to-client traffic

By default the tunnel addresses themselves are not reachable: a client reaches
only the shared networks. Enable **Client-to-client** (`clientToClient`) on the
gateway to make the tunnel subnet routable for every client:

- A flow to the gateway's tunnel address (the first address of the subnet)
  goes to the same port on the gateway's loopback address.
- A flow to another client's tunnel address is relayed by the gateway to that
  client. The client delivers it to the same port on its own loopback address
  only when its LAN Link outbound enables **Allow incoming**
  (`allowIncoming`). Otherwise the flow is dropped.

Both TCP and UDP are supported, over IPv4 and IPv6 tunnel addresses alike;
an IPv6 tunnel address maps to `::1`. Services bound only to loopback become
reachable this way, so enable these options only for trusted clients. A client
with **Allow incoming** keeps its link up from startup instead of waiting for
outgoing traffic. Clients pick up the tunnel subnet routes automatically when
they connect, and invitations issued while the option is on carry them from the
start. The gateway host itself does not route to client addresses.

While client-to-client is on, each client's node editor lists the gateway's
other clients with their names, tunnel addresses and whether they are online.
The gateway sends the list over the link, encrypted with the invitation's
token, and only when it changes.

### Auto connect

A LAN Link outbound normally starts its link the first time a connection uses
it. Turn on **Auto connect** (`autoConnect`) on the node to connect it when the
service starts or the node is saved, and to keep it connected while no
selector or rule uses it. The same switch is available for WireGuard
(the handshake starts right away, and peers without a keepalive get a 25-second
one) and Tailscale (the node joins the tailnet right away). A failed attempt is
retried with backoff.

## Manual Peer Tunnel configuration

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
can prevent a direct connection. Peers also advertise a private address from
their selected UDP interface. A peer on the same subnet can authenticate and
verify that address with a round-trip probe. The verified LAN path takes
priority over the public mapping. Peers sharing a public IP give the LAN probe
a short head start. If the LAN path fails, the public mapping can still be used
when the network supports NAT loopback. A direct path remains usable briefly
if discovery becomes unreachable. Both peers stop forwarding when their last authorization expires,
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
