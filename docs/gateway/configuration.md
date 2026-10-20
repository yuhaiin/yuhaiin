# HTTP Gateway v2 configuration

HTTP Gateway is configured through a **Gateway-owned workspace document**. Each
Gateway contains its own listener, HTTP/TLS interception settings, HTTP policies, backend pools,
URL filters, and fallback. The old separate `gateway.config.*` and
`gateway.resource.*` management APIs have been removed.

## Model

```text
Workspace (version=2, revision)
└─ gateways[]
   ├─ listener?             optional HTTP/HTTPS listening socket
   ├─ interception?         HTTP/TLS handling for Route-selected streams
   ├─ policies[]            ordered HTTP conditions and actions
   ├─ backendPools[]        pools owned by actions in this Gateway
   ├─ filters[]             per-Gateway URL filters
   └─ fallback              action when no policy matches
```

Rules and backend pools cannot be shared between Gateways and cannot be left
orphaned. A policy contains its condition and action; policies run in ascending
numeric `priority`, then ID order, with first-match semantics. The fallback
runs when no enabled policy matches. An action can still select an existing
Node/Selector/Direct via the normal outbound resolver.

The management API uses authenticated JSON RPC POSTs:

| RPC | Request | Result |
| --- | --- | --- |
| `gateway.workspace.get` | `{}` | Complete v2 document |
| `gateway.workspace.put` | Complete document and current revision | Validated, persisted and activated document |
| `gateway.filters.refresh` | `{"id":"..."}` | Updated v2 document |
| `gateway.status` | `{}` | Request and backend status |
| `gateway.statistics.reset` | `{"id":"gateway-id"}` or `{"id":""}` | Reset one or all Gateway counters |
| `gateway.test` | `{gatewayId,url,method,inboundId,sourceIp,process,headers}` | Saved-policy match trace |
| `gateway.ca.status` | `{}` | Public CA metadata |
| `gateway.ca.generate` | `{revision}` | New CA status |
| `gateway.ca.import` | `{revision,certificatePem,privateKeyPem}` | Imported CA status |

Example for a **new empty database**:

```sh
API=http://127.0.0.1:50051
curl -fsS "$API/api/v2/rpc/gateway.workspace.get" \
  -H 'Content-Type: application/json' --data '{}'
curl -fsS "$API/api/v2/rpc/gateway.workspace.put" \
  -H 'Content-Type: application/json' \
  --data-binary @docs/gateway/examples/http-reverse.json
```

The examples in `examples/` are full v2 documents, **not incremental
patches**. To edit an existing workspace, load it, preserve unrelated Gateways,
and submit its latest `revision`. HTTP 409 means the document has changed:
reconcile before retrying.

## Persistent statistics

Gateway request, block, forward, error, TLS/protocol failure and total duration
counters are saved to SQLite every five seconds and on graceful shutdown.
Counters are restored at startup and survive policy edits for the same Gateway
ID. Deleting a Gateway deletes its statistics in the same configuration
transaction; re-creating that ID starts with zero counters. The reset RPC can
clear one Gateway or all of them without editing configuration. A hard crash
may lose up to the last interval of unflushed counts.

The in-memory atomic counters remain the source for live status and Prometheus.
Backend health, active requests and last selected outbound are runtime-only.
Statistics are intentionally excluded from configuration-only backups.

## Source and Routing separation

A Gateway listener accepts direct HTTP/HTTPS connections. Configure the Gateway’s
`interception` mode directly, then add an explicit `HTTP Gateway` action in the
existing L4 Routing editor and apply Routing. Routing controls which Inbounds
and connections reach the Gateway; no additional Inbound attachment is required. Ordinary Route
priority and Block behavior remain authoritative. Routing and Gateway are not
yet a single transaction or activation snapshot.

HTTPS MITM additionally requires a generated/imported Gateway CA, explicit
domain allowlist, and client trust in the public CA. Unsupported/ECH/pinned TLS
flows cannot be forcibly decrypted. GREASE ECH can be intercepted like normal
TLS. Real ECH inner ClientHello data remains encrypted; Gateway uses the visible
outer name and some clients may retry with ECH disabled. QUIC/HTTP3 is not
intercepted.

A listener's `tlsMode: "termination"` uses its regular site certificate and
private-key file paths. It does not use the MITM CA. Non-loopback listeners
require explicit source CIDRs. Without configured management authentication,
Gateway RPCs are restricted to local peers/origins.

## Persisted format and backups

The SQLite `gateway_configuration` row persists the **versioned nested
workspace**, not the old flat Config object. Existing databases holding a
legacy flat document are intentionally **not migrated** and will reject
Gateway workspace load. Export, discard, or reset that old Gateway configuration
before adopting v2. Do not silently coerce an old document into the new
schema. Ordinary config backups exclude Gateway CA private-key material:
preserve its key through a protected database snapshot or separate import.

The HTTP engine still compiles an internal representation of policies, pools and
Gateway interception settings. This is a runtime implementation detail, not a second
supported persisted or public configuration format.

The tester evaluates the saved HTTP policy and admission without making an
upstream request; it does not simulate the preceding L4 Routing decision.
Use Routing Tester to confirm the Gateway action and Gateway Statistics to
verify that requests actually arrived. See [route handoff](route-handoff.md)
and [CA management](certificate-authority.md).
