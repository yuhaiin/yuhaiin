# Network diagnostics

The Web UI's **Network diagnostics** entry runs one on-demand diagnosis on the
backend device. Desktop and Android WebViews use the same page. Native clients
can call `AppInstance.Diagnostics.Run(ctx, tools.DiagnosticRequest{Host: host})`
or the authenticated `POST /api/v2/rpc/tools.diagnostics` operation with
`{"host":"www.cloudflare.com"}`. The REST-style path in the generated frontend
client is mapped to that RPC operation, not registered as another HTTP endpoint.

The report contract lives in `pkg/contract/tools/diagnostics.go`. Schema version
1 returns ordered checks, stable status/message/finding codes, timings, evidence,
and a portable plain-text report. The UI supports copying and downloading it.
Blank input uses `www.cloudflare.com`; input must be a DNS hostname without a
URL scheme, port, path or user information. Internationalized domains should be
entered in their ASCII/punycode representation.

## Checks and interpretation

| Check | Evidence | Scope |
| --- | --- | --- |
| TUN | Stored enablement, registered listener, driver, MTU, stream/packet/ping ingress counters | Counters are cumulative since the listener started. Registration does not prove current forwarding or correct system routes. |
| DNS A / AAAA | Real answers via the configured resolver and hosts path | Bypasses FakeIP allocation. Existing DNS cache entries can be used. An absent AAAA record is a warning, not DNS failure. |
| Direct IPv4 / IPv6 | TCP connections to `1.1.1.1:443` / `[2606:4700:4700::1111]:443` | Bypasses target DNS and application routing; uses the core's direct dialer and interface/VPN protection. Tests one control endpoint per family, not family reachability through every proxy. |
| Route | Mode, tag, resolver and destination for `host:443` | Uses active routing rules. Process and inbound metadata are absent, so actual app traffic can match differently. An intentional block is flagged for review. |
| Routed HTTPS | Verified TLS and HTTP response through hosts and routing | Does not traverse the TUN ingress. Any HTTP status demonstrates a response; redirects are recorded without following them. |
| Selected TCP node HTTPS | Verified TLS and HTTP response through the selected TCP node | Separate from routing: rules may choose direct or a tagged outbound instead. The selected UDP node and UDP forwarding are not tested. |

Disabled IPv6 is skipped. Failed probes show safe error categories (timeout,
TLS verification, connection refused, unreachable, DNS lookup or generic failure)
and guidance for further comparisons. They do not unconditionally label a node,
resolver or entire IP family as broken. A core HTTPS success still requires
checking TUN capture, OS routing or app DNS if applications fail.

## Resource and privacy behavior

Each network probe has a six-second context deadline; the run has a fifteen-second
context deadline. Probes run concurrently, with at most one diagnosis per core
instance (`429` for a duplicate run). The frontend bounds remote API waiting to
twenty seconds and aborts requests on cancel or navigation. No periodic polling,
background probe timers or configuration changes are performed by diagnostics.

Ingress tracking adds three atomic counters per listener; incrementing them does
not allocate. They reset when a listener is recreated.

The exported report includes the target hostname, DNS answers, routing labels,
platform, version and TUN counters. It excludes node configuration objects,
credentials and raw dialer errors/logs. It stays in the browser unless the user
copies/downloads it; there is no report upload service. Review operational details
before sharing it.
