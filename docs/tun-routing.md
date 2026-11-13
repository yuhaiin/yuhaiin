# TUN routing modes

A TUN protocol's `routing` object selects the destinations the TUN captures.
An absent or empty `mode` keeps the legacy `routes`/`excludes` lists exactly as
before (desktop route tables install both lists; Android passes `excludes` to
`VpnService.Builder.excludeRoute`, or applies its own route profile when
`routes` is empty). Saved legacy configurations are never rewritten.

```json
"routing": {
  "mode": "global | non_private | custom",
  "includeCidrs": ["10.8.0.0/16"],
  "bypassCidrs": ["203.0.113.0/24"],
  "geoipCountries": ["JP", "US"],
  "geoipInvert": false
}
```

Fields a mode does not use are kept (so switching modes in the editor loses
nothing) but still validated. CIDRs accept `a.b.c.d/n`, IPv6 prefixes and
single addresses; host bits are masked. Invalid entries, zones and `file:`
sources are rejected on save instead of being ignored.

## Route generation

`pkg/inbound.GenerateTunRoutes` produces one route set used by every platform:

    routes = ((base − built-in exclusions) ∪ include) − bypass − never-routed

| Mode | base | built-in exclusions | include |
| --- | --- | --- | --- |
| `global` | `0.0.0.0/0`, `::/0` | `0.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/3`, `fe80::/10`, `ff00::/8` | ignored |
| `non_private` | `0.0.0.0/0`, `::/0` | global's plus `10/8`, `100.64.0.0/10`, `172.16/12`, `192.168/16`, `fc00::/7` | adds back excluded networks |
| `custom` | selected countries, or with `geoipInvert` the non_private result minus those countries | none | routed as given |

Never-routed: `127.0.0.0/8` and `::/16` (unspecified, loopback, IPv4-mapped;
NAT64 `64:ff9b::/96` stays routable). Aligned blocks keep the route count low:
global needs about 50 routes and non_private about 90.

Bypass always wins over include. Set operations are exact (`go4.org/netipx`),
and the result is the minimal prefix list (duplicates, contained and adjacent
prefixes merged). A `/0` result is split into two `/1` routes. More than
16384 routes is an error; nothing partial is installed. Routes for address
families without a TUN address (or IPv6 disabled globally) are dropped.
FakeIP routes (`autoFakeIpRoute`) are added on top and are unaffected by
bypass.

GeoIP prefixes come from `MaxMindDB.PrefixesByCountries`: every network of the
search tree is visited (records shared by several networks are decoded once
per offset, but each network is kept), matched on `country.iso_code`, and the
last query is cached per database generation.

## Runtime

Generated routes are runtime state; the stored inbound keeps only `routing`.

- **Desktop**: a change limited to route selection (to a routing mode) updates
  system routes in place through the existing `RouteManager` (add new, then
  delete obsolete; failed additions roll back). The device, listeners and
  post-up/down commands are untouched. Saving the same TUN again retries.
- **Android**: the platform config carries the generated `routes` and
  `routeMode`. The app then installs exactly those routes plus the TUN subnets
  and FakeIP routes, ignores its route profile and the legacy `2000::/3`
  catch-all, and uses no `excludeRoute`, so all API levels get the same set.
  The interface is rebuilt make-before-break, as for other platform changes.
- **GeoIP updates** regenerate TUNs that select countries; **network changes**
  re-synchronize desktop TUN routes.
- If generation fails (GeoIP database not loaded, too many routes) or the OS
  refuses a route, the TUN keeps running in the `degraded` state with the error,
  and the next save, GeoIP update or network change retries.

## Existing routes and macOS

With a routing mode, a prefix the system already routes through another
interface (RTM_ADD `EEXIST` on macOS, a foreign table-63 route on Linux) is
left to that interface instead of failing the update; it is retried on later
updates. A matching route on the TUN itself is borrowed and never deleted.
Legacy route lists keep the previous all-or-nothing behavior. Longest-prefix
matching means more specific existing routes (LAN subnets, Tailscale
`100.64.0.0/10`, other VPNs) keep priority on macOS and Windows. Stopping the
TUN deletes only routes it created. yuhaiin's own outbound sockets keep using
the existing `IP_BOUND_IF`/`IPV6_BOUND_IF` binding, so the `/1` routes do not
loop. On Linux the TUN table is consulted by policy rule before `main`, so a
global TUN also captures LAN destinations; use non_private or bypass CIDRs.
