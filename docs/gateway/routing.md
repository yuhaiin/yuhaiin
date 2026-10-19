# HTTP rules, filtering and testing

Conditions have exactly one of `all`, `any`, `not`, or a leaf `field`. Empty
conditions match all requests. Leaves support `host`, `path`, `url`, `method`,
`header`, `query`, `inbound`, and `process`. Operators are `exact`, `prefix`,
`suffix`, `domain`, `regex`, and `present`. Header/query leaves require `key`.
Inbound leaves use exact stable inbound IDs for reference integrity. A domain
match includes that domain and its subdomains. Regex uses Go's regexp engine.

Example rules selecting different existing outbound nodes per request:

```json
[
  {
    "id": "api", "name": "API via A", "enabled": true, "priority": 10,
    "match": {"field": "path", "operator": "prefix", "value": "/api/"},
    "action": {"type": "forward", "outbound": {"type": "node", "id": "node-a"}}
  },
  {
    "id": "downloads", "name": "Downloads via B", "enabled": true, "priority": 20,
    "match": {"field": "path", "operator": "prefix", "value": "/download/"},
    "action": {"type": "forward", "outbound": {"type": "node", "id": "node-b"}}
  }
]
```

Use this with an interception-only Gateway whose default action is `forward`
with outbound `direct`, and attach both rule IDs. For a reverse listener use
`reverse_proxy` and an authorized configured Upstream instead of `forward`.
Forward requires the admitted original destination; a reverse listener cannot
become an arbitrary forwarding proxy using an untrusted request Host.

Outbound types are `inherit_route`, `direct`, `node`, `selector`, and the reused
Contract `default` for the current global selected node. Every request resolves
the effective target before pooling. L4 Block decisions and existing loop checks
remain enforced. Identical effective outbound/origin/TLS profiles can share a
connection; different effective proxy instances cannot. Physical connection
statistics remain in Connections, while request counters and latest selected
outbound appear in Gateway Statistics.

For a single URL ad rule use `block` with status 204 and a path condition, as in
the HTTP example. A `respond` action supports text/JSON and response headers;
`block` supports 204/403/404/451 or another final HTTP status. Redirect supports
301/302/307/308 and detects a redirect to the same URL. Avoid using MITM for
ordinary domain-only blocking; the existing Route/DNS domain rules already do it.

Filter lists use this explicitly bounded Adblock-style subset:

```text
! comments and [Adblock Plus ...] metadata are ignored
||example.com/ads/*
@@||example.com/ads/allowed|
||tracker.example^
```

`||` anchors the domain and its subdomains; a path uses `*` wildcards and an
optional final `|` anchor. `@@` exceptions override matching block entries.
Domain rules are indexed by host, so unrelated domains do not scan all regexes.
Unsupported options (`$script`, etc.), cosmetic rules (`##`), scriptlets,
unanchored regex, and unsupported separators are rejected and counted with line
numbers in Runtime Status / URL filters. They are not reinterpreted as normal
rules. Static text is persisted in SQLite. A remote URL is updated explicitly
using **Update remote filter**; downloads are capped at 4 MiB, use verified TLS,
do not follow redirects, and retain old rules if download/validation/save fails.

The Rule tester uses the running saved snapshot and does not contact upstreams:

```sh
curl -fsS "$API/api/v2/rpc/gateway.test" \
  -H 'Content-Type: application/json' --data '{
    "gatewayId":"site", "url":"https://app.example.com/ads/banner.js",
    "method":"GET", "inboundId":"tun", "headers":{}
  }'
```

The result contains ordered match steps, selected rule/action/upstream/outbound,
and whether HTTPS parsing requires termination or MITM. Filter decisions are
included. Process matching depends on metadata availability and the global
process-lookup setting; it cannot recover a process that the OS does not expose.

For the five Spotify URL denylist expressions, see the [complete configuration
and L4 admission steps](route-handoff.md#spotify-example).
