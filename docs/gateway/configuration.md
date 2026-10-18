# Configuration and management API

Open **HTTP Gateway** in the paired Web UI. The editor has Gateways, HTTP rules,
Upstreams, Interception, URL filters, TLS/CA, Rule tester, and Statistics views.
**Save and activate** submits one revisioned config. Backend errors retain the
draft. Resource IDs are stable; lower numeric rule priority runs first, then ID
order breaks ties. The first matching enabled rule wins. Rules are attached to a
Gateway with `ruleIds`; its default action runs if none match.

The actual API uses authenticated JSON RPC POSTs, like the rest of `/api/v2`:

| Operation | Request | Result |
| --- | --- | --- |
| `gateway.config.get` | `{}` | Complete editable config |
| `gateway.config.put` | Complete config with current revisions | Saved, activated config |
| `gateway.resources.list` | `{}` | All Gateway resources |
| `gateway.resource.get` | `{kind,id}` | Typed resource |
| `gateway.resource.put` | `{kind,id,gateway}` / `rule` / `upstream` / `filter` | Activated config |
| `gateway.resource.delete` | `{kind,id,revision}` | Activated config |
| `gateway.status` | `{}` | Request, TLS, filter, duration, backend-health status |
| `gateway.test` | `{gatewayId,url,method,inboundId,sourceIp,process,headers}` | Match trace and action |
| `gateway.filters.refresh` | `{id}` | Updated and activated config |
| `gateway.ca.status` | `{}` | Public CA status/certificate/cache counts |
| `gateway.ca.generate` | `{revision}` | New/rotated public CA status |
| `gateway.ca.import` | `{revision,certificatePem,privateKeyPem}` | Public CA status only |

`kind` is `gateway`, `rule`, `upstream`, or `filter`. Create with entity revision
zero; updates/deletes require the current entity revision. Bulk saves also require
the current config revision. HTTP 409 signals a conflict. To reorder, change rule
priorities and save. To enable/disable, change `enabled` and save. Upstream/Rule
references must be removed before deleting those resources. Gateway references
protect Nodes, Selectors and Inbounds from deletion through existing stores.

Example for a new empty database (set `API` and authentication for your instance):

```sh
API=http://127.0.0.1:50051
curl -fsS "$API/api/v2/rpc/gateway.config.get" \
  -H 'Content-Type: application/json' --data '{}'
curl -fsS "$API/api/v2/rpc/gateway.config.put" \
  -H 'Content-Type: application/json' \
  --data-binary @docs/gateway/examples/http-reverse.json
```

For an existing database, edit the result of `config.get` and preserve unrelated
resources/revisions. Example files describe complete configs, not patches. The
frontend generates IDs and reuses the current Node/Selector picker. All headers
are maps of string arrays; an empty array deletes that header. Managed framing
and hop-by-hop headers cannot be configured manually.

`listen` is empty for interception-only Gateways. Loopback listeners may use an
empty source ACL. Non-loopback listeners require explicit `allowedSources` CIDRs.
Use `tlsMode: "termination"` with backend-local `certificateFile` and `keyFile`
paths for HTTPS. These certificates are independent of the interception CA.
The management API uses existing Basic authentication. Without configured
authentication, Gateway RPCs accept only loopback peers and local browser origins.
Configure authentication and TLS for remote clients or a hosted cross-origin UI.

Config backups include Gateway config and references. They deliberately exclude
the CA private key; see the [CA recovery procedure](certificate-authority.md).

Rule tester evaluates saved configuration without making an upstream request.
Leave `inboundId` empty for an ordinary reverse listener (site TLS does not
require MITM). For interception, provide its inbound ID and, when restricted,
client source IP and process. MITM eligibility includes the domain exclusions,
URL port and admission constraints. A rule's inherited outbound includes its
Upstream fallback; `inherit_route` ultimately uses the existing L4 Route.
The visual editor removes attached rule IDs and owned filters/interceptions
alongside resource deletion in one draft, and prevents deleting used Upstreams.
