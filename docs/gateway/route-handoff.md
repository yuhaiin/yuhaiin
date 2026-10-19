# Route chooses whether to enter a Gateway

Use the existing **Routing** editor to create a rule with action **HTTP Gateway**
and choose the Gateway. This adds a TCP action to the existing L4 matcher, not a
second domain/process routing engine.

```text
Inbound -> existing sniffing (if enabled) -> FakeIP/hosts recovery -> L4 Route
  direct/proxy/block -> existing forwarding (no Gateway probe)
  gateway           -> Gateway inbound/domain/TLS admission -> HTTP policy
                         not admitted -> normal L4 rules, skipping Gateway actions
```

Rules keep their current order. A Direct/Proxy/Block rule before the Gateway rule
wins. Gateway actions are ignored for UDP, DNS and ping; the remaining ordinary
rules/default continue to apply. Gateway actions cannot be the global routing
default or an HTTP Gateway's outbound target.

A Gateway needs both configuration layers:

1. **Routing rule**: decide which TCP connections are candidates. Reuse existing
   host lists, process lists, inbound/network/port conditions and priorities.
2. **Gateway Interception**: authorize HTTP-only or explicitly allowlisted MITM
   on the chosen inbound, with domain exclusions/source/port/process limits.
   These permissions alone no longer divert application traffic.

Known destinations from SOCKS/CONNECT or recovered FakeIP are tested against the
admission domain scope before allocating readers or changing socket deadlines.
Existing sniffed Host/SNI can also reject a connection immediately. A numeric IP
without a recovered name is unknown, not an automatic domain mismatch: Host/SNI
probing remains available for it. After a positive prefilter, the actual Host/SNI
must still be admitted. Both the known destination and HTTP/TLS authority must be
in scope; a permitted SNI does not widen an excluded destination.

When HTTP handling forwards a request, it skips Gateway actions and evaluates the
other L4 rules with the existing Route/NodeRuntime. Block checks are retained.
This applies to explicit HTTP outbounds too. No pipe, extra listener or second
TCP dial is inserted between the original connection and Gateway.

For ordinary connections classified by the gate, the routing result is pinned to
that connection and reused by its subsequent dial. HTTP request forks do not
reuse that connection decision: they still select their effective outbound per
request, preserving HTTP/2 isolation and selector changes.

Route admission happens once per connection, as with ordinary L4 routing.
Changing an L4 rule affects new connections. Changing Gateway interception
permissions revokes affected admitted sessions; changing HTTP rules affects
subsequent requests on surviving connections.

## Spotify example

The upstream [spotify-adblock project](https://github.com/abba23/spotify-adblock)
is an LD_PRELOAD library wrapping Spotify's URL request creation, not an HTTP
proxy server. Reuse its denylist in our Gateway; do not configure that repository
as an HTTP Upstream.

[The complete Spotify example](examples/spotify-filter.json) represents the five
URL regexes for regional `*-spclient.spotify.com` ads/ad-logic and
`spclient.wg.spotify.com` ads/ad-logic/gabo-receiver-service. It uses one HTTP rule
with **any** of five **URL / regex** leaves, action **block / 204**, and Gateway
default **forward / inherit_route**. It needs no fixed reverse-proxy Upstream:
allowed requests retain their original destinations and normal outbound choice.
The URL filter-list importer accepts the documented Adblock subset, not a TOML
`denylist` array or arbitrary regex; put these expressions in HTTP policy leaves.

Use the example as a complete new configuration only, or merge its resources into
the current config while retaining unrelated entries and revisions. Replace
`spotify-inbound` with the actual inbound ID, generate/import a CA, and explicitly
trust its public certificate in the client before HTTPS MITM.

Create the interception-only Spotify Gateway, its URL denylist rule and trusted
CA first. In the existing Routing editor create a host list containing
`*.spotify.com` (the existing host-list wildcard includes the root and subdomains), optionally combine it with the
Spotify inbound/process and TCP port 443, choose action **HTTP Gateway**, and
select that Gateway. Put it before a general Direct/Proxy catch-all.

This broad host list admits Spotify connections, including permitted requests.
To narrow it further, list the actual regional spclient hostnames instead. The
L4 rule cannot distinguish `/ads/` from a permitted path on the same hostname;
that decision happens per HTTP request after admission and HTTPS decryption.
Certificate pinning or a client that does not trust the CA prevents that
inspection; passthrough cannot filter paths.

The corresponding existing Route draft shape is:

```json
{
  "rule": {
    "id": "spotify-to-gateway",
    "name": "Spotify HTTP filtering",
    "revision": 0,
    "mode": "gateway",
    "target": {"type": "gateway", "id": "spotify"},
    "rules": [{"type": "all", "all": [
      {"type": "host", "host": {"list": "spotify-hosts"}},
      {"type": "network", "network": {"network": "tcp"}},
      {"type": "port", "port": {"ports": "443"}}
    ]}]
  },
  "lists": [{
    "id": "spotify-hosts",
    "name": "Spotify hosts",
    "type": "host",
    "revision": 0,
    "source": {"type": "local", "local": {"lists": ["*.spotify.com"]}}
  }]
}
```

Create this through the normal Route editor/RPC, then apply Routing changes.
Replace the Gateway ID with the existing saved ID. The same SQLite transaction
validates the Gateway reference. Saved and currently applied Route rules both
protect the Gateway from deletion; remove the rule and apply before deleting it.
Disabling a referenced Gateway is allowed and returns new traffic to normal
routing. Existing interception-only configs require a corresponding L4 action;
Gateway reverse listeners retain their separate role. The old `reverse_http`
and `http_termination` protocol types have been removed; see
[configuration changes](troubleshooting.md).

For IP-only TUN traffic, supply FakeIP recovery or enable the existing sniffing
when routing by domain. Without either, an L4 domain rule cannot know the hostname.
Alternatively select a known destination IP/CIDR in the existing host list.

The Gateway Rule tester evaluates HTTP policy/admission for the chosen Gateway;
it does not simulate the preceding L4 routing decision. Use the existing Routing
tester to confirm its Gateway action, and Gateway Statistics to verify actual
requests arrived.

## Other avoided work

Admission rules are indexed by inbound; disabled Gateways and passthrough/off
entries have no active interception runtime. Source/known-domain rejection occurs
before process lookup. Process lookups needed by HTTP rules happen only after
protocol/domain admission, and established process metadata is reused.

Only upstreams referenced by the Gateway's default/enabled HTTP rules own runtime
backend state and health workers. All drafts, including unused upstreams, remain
validated during config saves. Unrelated filter hosts do not construct a URL
string; explicit block/respond actions do not evaluate filters whose result
cannot affect them. Probe buffers are 4 KiB; long HTTP header lines still replay
correctly up to the existing 64 KiB probe cap.
