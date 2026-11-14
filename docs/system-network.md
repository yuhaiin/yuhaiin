# System Network Manager

The System Network Manager (`pkg/sysnet`) is the only part of Yuhaiin that
changes operating system routing. It owns three things:

- **Routing**: which destinations the OS sends to a Yuhaiin TUN or to another
  interface (WireGuard, Tailscale, Ethernet, Wi-Fi, ...).
- **Forwarding** (Linux, macOS, Windows): letting other devices use this host
  as their gateway (side router), with optional NAT, or TProxy interception
  on Linux.
- **Interfaces**: discovery of the interfaces those rules refer to.

This is separate from proxy routing (route rules that pick a node by domain or
GeoIP). Proxy routing decides how Yuhaiin handles a connection it received;
System Network decides which connections the OS hands to Yuhaiin at all.

TUN inbounds only create and configure their device (name, MTU, addresses,
stack, FakeIP) and report it to the manager (`AttachTun`/`DetachTun`). They
install no destination routes. Routes a running TUN needs to work — its FakeIP
pools, and on macOS its own subnet — are *required routes* that the manager
installs and removes together with the rule routes.

## Configuration and status

The configuration is one JSON document (`settings_kv`, section
`system_network`), so it is included in configuration backups:

```json
{
  "routes": [{
    "id": "route-1", "name": "Internet via VPN", "enabled": true, "priority": 100,
    "match":  { "mode": "non_private", "includeCidrs": [], "bypassCidrs": [], "geoipCountries": [], "geoipInvert": false },
    "target": { "type": "tun_inbound", "inboundId": "tun" }
  }],
  "forwarding": {
    "ipv4": true, "ipv6": false,
    "rules": [{ "id": "lan", "name": "LAN", "enabled": true, "ingressInterface": "eth1",
                "sourceCidrs": ["192.168.20.0/24"], "destinationCidrs": [],
                "egress": { "type": "tun_inbound", "inboundId": "tun" }, "masquerade": false }]
  },
  "migrations": []
}
```

Targets:

| `type` | Identifies | Notes |
| --- | --- | --- |
| `tun_inbound` | `inboundId` | Resolved to the TUN's interface at runtime. Unavailable while the TUN is stopped; resynchronized when it starts again. |
| `interface` | `interfaceName` (+ `hardwareAddr`) | Any interface of the host, including ones other programs own. The hardware address finds it again after a rename. `gateway` / `gatewayV6` override detection. |
| `tproxy` | `inboundId` | Forwarding egress only (Linux): interception into a TProxy inbound, not a route. |
| `routes` | — | Forwarding egress only: follow the system routing table, which already contains the route rules. The only egress on Windows. |

Interface indexes are never saved; they are resolved on every update.

Runtime status is a separate resource. Each rule reports `active`,
`pending`, `degraded`, `conflict`, `unavailable`, `unsupported`, `disabled`
or `failed`, its IPv4/IPv6 route counts, conflicting prefixes, the rules that
override it and whether it is shadowed. Saving returns both the saved
configuration and the status after applying it: a save can succeed while the
OS rejects the update, and the UI shows that as a failure.

API (`/api/v2`, `settings:read` / `settings:write`):

| Method | Path | |
| --- | --- | --- |
| GET | `/system-network/config` | Saved configuration |
| PUT | `/system-network/config` | Validate, save, apply; returns `{config, status}` |
| GET | `/system-network/status` | Runtime status and platform capabilities |
| GET | `/system-network/interfaces` | Interfaces, TUN/TProxy inbounds, missing targets |
| POST | `/system-network/preview` | Route counts and shadowing for a draft, without applying |

## Route policy

`pkg/sysnet/policy` is pure and shared by all platforms and the preview.

Each rule's match is turned into an exact address set:

    set = ((base − built-in exclusions) ∪ include) − bypass − loopback

| Mode | base | built-in exclusions | include |
| --- | --- | --- | --- |
| `global` | `0.0.0.0/0`, `::/0` | `0.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/3`, `fe80::/10`, `ff00::/8` | ignored |
| `non_private` | `0.0.0.0/0`, `::/0` | global's plus `10/8`, `100.64.0.0/10` (CGNAT, Tailscale), `172.16/12`, `192.168/16`, `fc00::/7` (ULA, Tailscale) | adds back excluded networks |
| `custom` | selected GeoIP countries, or with `geoipInvert` the non_private set minus them | none | used as given |

Loopback means `127.0.0.0/8` and `::/16` (unspecified, loopback,
IPv4-mapped; NAT64 `64:ff9b::/96` stays routable). Bypass always wins over
include; include wins over the built-in exclusions. Set operations are exact
(`go4.org/netipx`) and produce minimal prefixes; a `/0` is split into two
`/1` routes so the system default route stays in place.

GeoIP prefixes come from `MaxMindDB.PrefixesByCountries`, which visits every
network of the database (records shared by several networks are decoded once
per offset, every network is kept) and caches the last query per database
generation. A GeoIP database update regenerates the rules. While the
database is missing, a rule keeps its last successful routes and reports
`degraded` with `stale` instead of losing its routes.

**Priority and conflicts.** Rules are evaluated by ascending `priority`, then
list order. The first rule that matches a destination owns it: every later
rule loses whatever earlier rules already own, computed as an exact set
difference before anything is installed. So one prefix never goes to two
targets, and the configured order — not the OS's longest-prefix match —
decides the winner. Overlaps are reported as `overriddenBy`; a rule left with
nothing is `shadowed`. Required TUN routes are evaluated before all rules.
Disabled rules and rules whose target is unavailable take no part, so their
destinations fall through to the next matching rule.

Limits: 16384 routes per rule and 32768 in total. A larger result is rejected
and the previous routes stay installed.

Only families the target can carry are routed: a TUN without an IPv6 address
(or with IPv6 disabled globally), or an interface without an address or
gateway of a family, gets no routes of that family.

## Interface discovery

`pkg/sysnet/iface` lists interfaces with their addresses, MTU, state, type
(ethernet, wifi, tunnel, bridge, virtual, loopback) and gateways read from
the main routing table (default route first). Type comes from netlink link
types on Linux, the interface type on Windows, and name/flag heuristics on
macOS.

Ownership shown to users: **Yuhaiin** for attached TUNs (with the inbound
name), **External** for tunnels other programs created, **System** for the
rest. Yuhaiin never deletes, recreates or reconfigures interfaces it does not
own.

Gateways: point-to-point interfaces (TUN, WireGuard, Tailscale, utun) need
none. Broadcast interfaces (Ethernet, Wi-Fi) need one per family: an explicit
gateway must lie inside one of the interface's subnets (IPv6 link-local is
allowed), otherwise the detected gateway is used; with neither, the rule fails
with a message asking for one. A network behind another router is never
treated as directly connected.

The manager resynchronizes on configuration saves, TUN start/stop, FakeIP
pool changes, GeoIP updates, the shared network monitor (default-route
changes) and a 3-second poll of interface identities, addresses and gateways,
so rules follow interfaces that disappear, return or change index.

## System routes view

`GET /api/v2/system-network/routes` (`systemNetwork.routes`, settings read)
returns the routing table the OS uses right now. It is read-only. The System
Routes tab in the System Network page shows it, groups Linux routes by table,
can filter to Yuhaiin's routes and lists the Linux policy rules. At most 5000
routes are returned (`truncated` is set beyond that).

Each route Yuhaiin owns has `yuhaiin: true`, a `source` and, where one
applies, the rule it comes from (`ruleId`, `ruleName`):

| source | meaning |
|---|---|
| `rule` | installed for a route rule |
| `required` | keeps a TUN working (its subnet, FakeIP pools); the rule is the TUN inbound |
| `forwarding` | in a forwarding table (6300+, or the TProxy table 6299) |
| `vpn` | passed to the Android VPN for a route rule |
| `stale` | carries Yuhaiin's mark but is not in the current configuration; removed on the next start |

How a route is recognized: the manager remembers which rule each installed
prefix belongs to and matches prefix and interface (on Linux, in table 63).
On Linux, routes and policy rules Yuhaiin creates also carry the protocol
number `0xa5`, which marks forwarding and left-over routes.
On macOS the table comes from the routing socket (sysctl RIB) and on Windows
from `GetIPForwardTable2`; neither has tables, so routes are listed flat.

Android does not let apps read the kernel routing table (netlink dumps are
denied). The app answers the `routes.list` host call with the routes of
every network from `ConnectivityManager.getLinkProperties(network).routes`,
flagging the networks of its own VPN (`NetworkCapabilities.ownerUid`, API 30+;
before that, Android's single VPN is taken as Yuhaiin's). Routes of the
Yuhaiin VPN are marked: those of a route rule as `vpn`, the rest as
`required`. Policy rules are not available. An app without `routes.list`
shows only the routes passed to the VPN (`readable: false`).

## Linux policy routing

All rule and required routes go into one dedicated table, **63**, selected by
one policy rule per family (`30001` IPv4, `30002` IPv6) ahead of `main`:
`not fwmark 0x500 lookup 63`. Packets carrying the Socket Protection mark
skip the table (see [Outbound socket routing](#outbound-socket-routing)); a
rule of ours from an older version without the mark exclusion is replaced on
the next update, and another program's rule at the same priority is reported
as a conflict, never replaced. The
table may hold routes to many interfaces at once; prefixes are unique by
construction. The System Network Manager is the only owner of the table and
the two rules — TUNs no longer add or remove them.

Every route carries the routing protocol `0xa5`. On start the manager deletes
routes with that marker left by a crashed run; routes in table 63 without it
belong to someone else and are never removed or overwritten. If such a route
already uses a prefix on another interface, that prefix is reported as a
conflict and retried on later updates. An identical route is reused but never
deleted.

Updates are a diff: new and changed routes first (target changes use
`RTM_NEWROUTE` replace), then removal of obsolete ones. A failed addition
rolls back what the update added or changed, so the previous routes stay in
effect. Failed deletions are retried. Stopping removes every owned route and
the policy rules.

Yuhaiin's own connections carry the mark and are routed by `main`, so routes
towards a TUN do not loop and need no interface binding. Because table 63 is
consulted before `main`, a global rule on Linux also captures other
applications' LAN destinations; use non_private or bypass CIDRs to keep them
local.

## Outbound socket routing

Route rules decide where **other applications'** traffic goes. Sockets
Yuhaiin opens for its own outbound traffic (proxies, DNS upstreams, QUIC,
Hysteria 2, WireGuard, MASQUE, VPN clients, audit delivery, ping) must never
enter Yuhaiin's own TUN, whatever the route rules say. Two separate mechanisms
handle that:

- **Socket Protection** keeps the socket out of the TUN.
- **Egress Selection** decides which interface it leaves through: by default
  the one the OS routing table would use for the destination, never the TUN.
  A configured network interface means "use exactly this interface" and is
  the only reason a socket is pinned regardless of destination.

```text
Applications ──> OS routing ──> route rules ──> Yuhaiin TUN / WireGuard / physical NIC

Yuhaiin proxy / DNS / QUIC / HY2 ──> Socket Protection ──> Egress Selection ──> physical or other NIC
                                         (never the TUN)
```

| Platform | Protection | Egress Selection |
|---|---|---|
| Linux | `SO_MARK 0x500` excluded by the TUN policy rule | the kernel routes each packet (`main` table); sockets stay unbound |
| macOS | `IP_BOUND_IF` / `IPV6_BOUND_IF` to the chosen interface | the OS route for the destination with the TUN excluded; interface-scoped defaults (`RTF_IFSCOPE`) keep bound sockets routable |
| Windows | `IP_UNICAST_IF` / `IPV6_UNICAST_IF` to the chosen interface | longest prefix, then lowest route + interface metric, TUN excluded |
| Android | `VpnService.protect(fd)` plus Android Network binding | the platform's underlying network |

While no Yuhaiin TUN is up, sockets are neither marked into a different path
nor bound: they follow the OS routing table like any other program.

**Linux.** Setting `SO_MARK` needs `CAP_NET_ADMIN`. Yuhaiin probes it once at
start. Without it the status is *degraded*: sockets fall back to the
interface binding used on macOS and Windows (correct, but each UDP flow then
uses one interface per destination socket). A marked packet that finds no
route in `main` fails with `ENETUNREACH`; it can never fall back into table
63. If `main` itself routes a destination through the TUN, the nftables
SkipMark rule (`mark 0x500 oif <tun> reject`) rejects it instead of letting it
loop. The forwarding rules (priorities 28999–29999) match on the input
interface only and are not affected; the TProxy mark `0x5953` is unrelated.
Listener sockets are marked too, so replies to clients leave through the
physical network, but are never bound.

**macOS.** A bound socket uses only routes scoped to its interface or, on the
primary interface, the global default. macOS installs a scoped default for
every non-primary interface with a router. When a VPN takes over the global
default, the former primary can be left with neither; Yuhaiin then installs a
scoped default (`default <router> ifscope <if>`) from the router it last saw
on that interface, only while the interface keeps the same addresses. Existing
scoped defaults are borrowed and never changed. Yuhaiin deletes only routes
it created, after checking the routing table still holds them with its
gateway, and removes them all when it stops. An interface without a known
router reaches only its directly attached networks.

**UDP with many destinations.** Where protection binds sockets (macOS,
Windows, Linux without `SO_MARK`), a direct UDP relay keeps one socket per
egress interface and picks it per datagram, so one flow can reach the
Internet through Ethernet and a LAN through Wi-Fi. Loopback and link-local
destinations are never bound. On Linux with the mark one socket serves every
destination.

The **Outbound** tab of the System Network page shows the method, the policy
rules (Linux), the egress chosen for Internet destinations, every interface
with its gateway, default-route metric and scoped defaults (macOS), and any
problem. It is read from `GET /api/v2/system-network/outbound`
(`settings:read`), which changes nothing.

Yuhaiin adds these OS objects for outbound routing, and removes them on stop:

| Platform | Object | Owner check | Cleanup |
|---|---|---|---|
| Linux | rules `30001`/`30002` `not fwmark 0x500 lookup 63` | protocol `0xa5`, priority, table | deleted with the System Network Manager; stale ones replaced on start |
| Linux | nftables `mark 0x500 oif <tun> reject` (SkipMark) | Yuhaiin's table | deleted with the TUN |
| macOS | `default <router> ifscope <if>` routes | gateway, interface index, `RTF_IFSCOPE` | deleted when no longer needed and on stop |
| Windows | none: sockets are bound, routes are not changed | | |

## Forwarding and NAT

A forwarding rule selects traffic arriving on an ingress interface, from
source CIDRs (empty means every device on that interface), optionally only
to some destinations, and sends it to an egress. Masquerade needs an egress
interface; it is not available with the `routes` egress.

### Linux

Forwarding is independent from routing and turned on per IP version.

- **sysctl**: `net.ipv4.ip_forward` and `net.ipv6.conf.all.forwarding`. The
  value before the first change is recorded and restored on stop, but only if
  it still has the value Yuhaiin wrote; a setting that was already on, or that
  another service changed meanwhile, is left alone. Enabling IPv6 forwarding
  makes Linux ignore router advertisements.
- **Policy routing**: each rule gets its own table (6300–6555) with its
  destinations (or the whole internet as two `/1` routes) via the egress, and
  one rule per source CIDR `iif <ingress> from <source> lookup <table>` at
  priority 29000+. Forwarding rules come before the route-rule table, so
  forwarded traffic leaves through its own egress.
- **Firewall**: one nftables table, `inet yuhaiin_sysnet`, replaced
  atomically on every update and deleted on stop. Other tables are never
  flushed or changed, and iptables is not used. Its `forward` chain accepts
  the configured sources from each ingress and drops other forwarded traffic
  from that ingress, so only selected devices are forwarded.
- **NAT**: off by default. With `masquerade`, sources leaving the egress are
  rewritten to the egress address — needed when the upstream router has no
  route back to the LAN.
- **TProxy**: the `prerouting` chain marks matching TCP/UDP and hands it to
  the TProxy inbound (`tproxy to :port`); a mark rule limited to the ingress
  (`fwmark 0x5953 iif <ingress> lookup 6299`, priority 28999) delivers it
  locally through `local default dev lo`. The `iif` limit matters: with
  `src_valid_mark`, a mark rule for every interface would make reverse-path
  checks treat the client's address as local and drop the packets.

Policy rules and routes carry the same `0xa5` marker; stale ones in the
managed ranges are removed when forwarding is first used. While forwarding is
unused the manager makes no kernel calls, so it also runs without
`CAP_NET_ADMIN`.

Side router example: on the LAN device (or DHCP server) set the gateway to
this host's LAN address, enable IPv4 forwarding, and add a rule
`ingress eth1, sources 192.168.20.0/24, egress <TUN>`.

### macOS

- **sysctl**: `net.inet.ip.forwarding` and `net.inet6.ip6.forwarding`
  through `sysctl(8)`, with the same ownership rules as on Linux.
- **PF**: all rules live in the anchor `com.apple/yuhaiin`. The default
  `/etc/pf.conf` already evaluates every `com.apple/*` anchor (`anchor` and
  `nat-anchor`), so `pf.conf` and other anchors are never edited. Before
  loading, the manager checks that the main ruleset evaluates those anchors
  and refuses with an explanation if a customized `pf.conf` does not. Rules
  are parsed first (`pfctl -n`) and then loaded into the anchor in one step,
  so a rejected ruleset leaves the previous one in place.
- **Enabling PF** uses the reference-counted `pfctl -E` token, released with
  `pfctl -X <token>` on stop; PF stays enabled when other software uses it.
- **Rules** (first match wins, in configuration order): traffic from the
  selected sources to this host itself passes; traffic to the rule's
  destinations is sent with `route-to (<egress> <next hop>)` — the gateway,
  or for utun and other point-to-point interfaces their own address, as for
  routes; other traffic from those sources follows the routing table;
  link-local multicast and broadcast pass; everything else that arrives on
  the ingress and is not for this host is blocked, so only selected devices
  are forwarded. Masquerade adds `nat on <egress> from <sources> -> (<egress>)`.
- **Not available**: TProxy interception (macOS has no TPROXY; it would need a
  separate `rdr` based inbound).

### Windows

- Windows has no global forwarding switch or policy routing. The manager
  turns on forwarding (`ForwardingEnabled` of the IP interface, per family)
  on each rule's ingress and on the interfaces forwarded traffic may leave
  through: interfaces with a default gateway, route rule targets and attached
  TUNs. It records which interfaces it changed and turns forwarding off again
  only on those, and only while it is still on.
- Forwarded traffic follows the routing table, including the System Network
  route rules, so the only egress is `routes`.
- **Not available**: limiting forwarding to source CIDRs (the API rejects
  them), a per-rule egress, NAT (WinNAT only serves one internal prefix and is
  meant for Hyper-V; ICS conflicts with other settings), and TProxy.

## Platform support

| | Linux | macOS | Windows | Android |
| --- | --- | --- | --- | --- |
| Route rules | ✓ | ✓ | ✓ | ✓ (VPN only) |
| Multiple targets / external interfaces | ✓ | ✓ | ✓ | – |
| Gateways for physical interfaces | ✓ | ✓ | ✓ | – |
| Policy routing (dedicated table) | ✓ | – | – | – |
| IPv4 / IPv6 forwarding | ✓ | ✓ | ✓ (per interface) | – |
| Forwarding source filter, per-rule egress | ✓ | ✓ (PF) | – | – |
| NAT | ✓ | ✓ (PF) | – | – |
| TProxy | ✓ | – | – | – |

The capabilities are part of the status, the editor offers only supported
targets and features, and the API rejects configuration a platform cannot
apply.

**macOS**: routes are added to the single system table with `RTM_ADD`
(point-to-point interfaces use their own address as next hop). There is no
policy routing: rule priority is enforced by the exact set difference, and
the kernel's longest-prefix match chooses between prefixes. If another
interface already has a route for the same prefix (`EEXIST`), that route
stays and the prefix is reported as a conflict instead of being overwritten.
A matching route on the same interface is borrowed and never deleted. Routes
via a utun disappear with it; routes via external interfaces left by a crash
are not cleaned up automatically. Forwarding uses PF as described above.

**Windows**: routes are added per interface LUID (`luid.AddRoute`), on-link
for point-to-point adapters. No policy routing; forwarding per interface as
described above.

**Android**: `VpnService` owns the only TUN. Rules may target only the
Yuhaiin VPN; the manager resolves them with the same engine and passes the
final route set to the platform VPN (`routeMode: "system_network"`). The app
then installs exactly those routes plus the TUN subnets and FakeIP routes,
without `excludeRoute`, so all API levels get the same set. Without a rule
for the VPN, the route profile chosen in the app applies as before. Rule
changes rebuild the VPN interface make-before-break. External interfaces,
several TUNs and forwarding are not available.

## Migration from TUN routing

Earlier versions kept routes on TUN inbounds (`routing`, `routes`,
`excludes`). These fields are now only read for migration, at startup and
whenever an inbound is saved (including restores of old backups):

- A routing mode becomes a rule with the same match targeting that TUN.
- Manual lists keep their earlier behavior: desktop installed `routes` and
  `excludes` alike, so both become include CIDRs of a custom rule; Android
  excluded `excludes` (API 33+), so they become bypass CIDRs, and with no
  `routes` Android used its route profile, so no rule is made.
- `file:` lists are read and copied once; invalid entries, which earlier
  versions ignored silently, are listed as warnings.

Rule IDs derive from the inbound and its settings, so repeating a migration
never creates duplicates. Rules of different TUNs are appended after existing
rules in inbound order and never dropped; overlaps show in the status. The
configuration is saved before the legacy fields are cleared from the inbound,
so an interruption only repeats an idempotent step. Each migration is
recorded in `migrations` and shown on the System Network page. TUN inbounds
ignore the legacy fields at runtime and changing only them never rebuilds a
TUN.

## Podman integration test

`scripts/integration/system-network-podman.sh` verifies real kernel behavior
in isolated containers. Everything runs in Podman network namespaces on
internal networks; the host's routes, rules, firewall and sysctls are not
changed (the script compares host state before and after). Rootless Podman
works: the router container is `--privileged` only to get writable
`/proc/sys/net`, nftables and TUN devices inside its own namespaces.

```text
client, client2 ──lan── router (System Network harness) ──up1── upstream 1
                                                      └──up2── upstream 2
```

```sh
scripts/integration/system-network-podman.sh
```

Requires `podman`, `go` and `jq`; the first run builds a small Alpine image
with iproute2 and nftables. The script builds `internal/sysnettest` (the real
manager with the Linux adapters) and the gated kernel tests, then checks:

- kernel tests: route manager lifecycle, ownership, stale cleanup, external
  routes; forwarding nftables table, foreign table preservation, sysctl
  restore;
- multiple TUNs and an external tunnel, priority, overlap and conflict
  reporting, interface removal and return, TUN stop/restart;
- global, non_private, include, bypass, custom CIDR, GeoIP and GeoIP reverse
  through `ip route get`, IPv4 and IPv6;
- forwarding: return route vs. masquerade, source restriction, egress
  selection, forwarding to a TUN, IPv6 forwarding;
- TProxy interception (skipped with a reason if the kernel lacks nft TPROXY);
- cleanup of routes, rules, nftables table and sysctls on stop.

It prints PASS / FAIL / SKIP for each check and exits non-zero on any
failure; skipped checks are never counted as passed.

### Outbound routing checks

Linux (as root, in fresh network namespaces; host routes are never changed):

```sh
CGO_ENABLED=0 go test -c -o dialer.test ./pkg/net/dialer
CGO_ENABLED=0 go test -c -o netlink.test ./pkg/net/netlink
sudo YUHAIIN_TEST_TUN_ROUTES=1 ./dialer.test -test.run TestRouting -test.v
sudo YUHAIIN_TEST_TUN_ROUTES=1 ./netlink.test -test.run 'TestLinux' -test.v
```

They build two NICs and a TUN table, and assert from each interface's transmit
counter where marked and unmarked UDP/TCP (IPv4 and IPv6) actually left.

macOS, with a UDP echo reachable through a second interface (for example a
local VM: `socat UDP-LISTEN:9999,fork EXEC:cat`):

```sh
YUHAIIN_TEST_MACOS_EGRESS_PEER=10.211.55.6:9999 go test -run TestMacOSEgress ./pkg/net/dialer
```

One relay conn must get answers both from 8.8.8.8 (through the primary
interface, bypassing a running TUN) and from the peer (through the second).

## macOS checks

```sh
scripts/integration/system-network-macos.sh          # unit tests, no root
sudo scripts/integration/system-network-macos.sh --live
```

`--live` additionally adds and removes routes for documentation prefixes via
`lo0`, loads rules into the `com.apple/yuhaiin` PF anchor, enables
forwarding, and checks that closing flushes the anchor, releases the PF token
and restores the sysctl. It never edits `/etc/pf.conf` or other anchors.
