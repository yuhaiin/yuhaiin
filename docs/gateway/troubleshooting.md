# Troubleshooting and configuration changes

| Symptom | Check |
| --- | --- |
| Save returns 409 | Reload the current config/entity revision and reconcile edits. Old runtime stays active. |
| Listen fails / source denied | Verify the address, port ownership, and explicit CIDR ACL. Public listeners require an ACL. |
| Forward returns 502 on a reverse listener | Use a configured reverse-proxy Upstream. Forward requires an admitted original destination. |
| HTTPS client rejects certificate | Verify CA fingerprint and installation, hostname/SAN and clock. Pinned clients/user-CA restrictions require exclusion or passthrough. |
| HTTPS upstream returns 502 | Verify actual backend hostname, SNI, trust PEM, outbound node and Route Block rules. Verification is enabled by default. |
| A path rule has no effect | Attach it to the Gateway, enable it, check priority, save/activate, and run Rule tester. Passthrough has no path visibility. |
| Upstream is unhealthy | Check HEAD health-path response, passive failure threshold, recovery delay and outbound reachability. |
| Remote filters do not update | Save edits first, then update explicitly. Sources must return 200 without redirects and contain supported rules under 4 MiB. |
| Process rule does not match | Check global process lookup mode and whether the platform exposes the initiating process. |
| gRPC / streaming ends early | Check application protocol support and configured request timeout/body limit. |
| Loop is rejected | Check backend aliases, listener ports and TUN recursion. Correct the destination rather than bypassing all routing. |

Gateway Statistics contains request/block/forward/error counters, total duration,
TLS/protocol failures, filter parse errors, latest selected outbound and backend
health. Existing Connections/Statistics records the physical upstream sockets
and bytes, so a reused HTTP/2 socket is one connection even if it carries many
requests. Authorization, Cookies and bodies are not logged by the Gateway. The existing
`/metrics` endpoint also exports `yuhaiin_gateway_*` request, failure, duration and
backend-health metrics; backend metric labels omit URL paths and queries.

The old `reverse_http` inbound and `http_termination` outbound are no longer
supported. There is no compatibility adapter or automatic configuration migration.
Use a Gateway listener with a reverse-proxy Upstream for HTTP reverse proxying;
use HTTP rules with rewrite/header actions for request modifications. Existing
entries cannot be activated or saved as new configurations. Unsupported Inbounds
remain visible through the list/detail API and the existing runtime-status panel
as `failed`, with the validation error and lifecycle event. Only that Inbound is
skipped during startup; valid listeners still start. Remove or replace the old
entry and configure Gateway explicitly. This change does not rewrite or delete
stored configuration rows automatically.

`reverse_tcp` keeps its existing contract and TCP forwarding behavior, with its
implementation now owned by `pkg/inbound`. TLS Auto and the separate
`tls_termination` outbound retain their TLS roles; neither enables MITM by itself.
Gateway upstream TLS verification remains enabled and supports explicit trust
certificates and server names without the removed legacy TLS override hooks.

A saved Gateway policy or listener that cannot start no longer aborts unrelated
proxy listeners. Its saved draft remains editable, and Gateway status/UI reports
`startupError`. Connections explicitly routed to that failed Gateway are closed
until a valid configuration is saved; they do not bypass its HTTP policy. Gateway
rules/upstreams are validated together, rather than partially activating a policy.

Run the reproducible unit/integration/race checks in [benchmarks](benchmarks.md).
Real privileged TUN/TProxy/Redir/WireGuard traffic needs an
appropriate local test environment; synthetic stream tests do not prove OS
installation or every third-party client works. HTTP/3 Gateway, ECH decryption,
pinning bypass, client-private-key impersonation, full browser Adblock syntax,
automatic remote-list scheduling and hardware-backed CA keys are not implemented.
