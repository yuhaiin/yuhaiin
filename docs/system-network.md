# System Network Manager

The System Network Manager (`pkg/sysnet`) is the only part of Yuhaiin that
changes operating system routing. It owns three things:

- **Routing**: which destinations the OS sends to a Yuhaiin TUN or to another
  interface (WireGuard, Tailscale, Ethernet, Wi-Fi, ...).
- **Forwarding** (Linux): letting other devices use this host as their
  gateway (side router), with optional NAT or TProxy interception.
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

## Linux policy routing

All rule and required routes go into one dedicated table, **63**, selected by
one policy rule per family (`30001` IPv4, `30002` IPv6) ahead of `main`. The
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

Yuhaiin's own connections bind to the default interface, so routes towards a
TUN do not loop. Because table 63 is consulted before `main`, a global rule
on Linux also captures LAN destinations; use non_private or bypass CIDRs to
keep them local.

## Linux forwarding and NAT

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

## Platform support

| | Linux | macOS | Windows | Android |
| --- | --- | --- | --- | --- |
| Route rules | ✓ | ✓ | ✓ | ✓ (VPN only) |
| Multiple targets / external interfaces | ✓ | ✓ | ✓ | – |
| Gateways for physical interfaces | ✓ | ✓ | ✓ | – |
| Policy routing (dedicated table) | ✓ | – | – | – |
| Forwarding, NAT, TProxy | ✓ | – | – | – |

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
are not cleaned up automatically. PF is not used, so forwarding is not
offered.

**Windows**: routes are added per interface LUID (`luid.AddRoute`), on-link
for point-to-point adapters. No policy routing and no forwarding.

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
