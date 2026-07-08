# HTTP API migration design

## 1. Background

The current control plane is generated from protobuf IDL and registered through
gRPC descriptors. `AppInstance.RegisterServer` registers every generated
`api.*Server` into both:

- a real gRPC server for HTTP/2 `application/grpc` requests
- an HTTP compatibility layer whose paths are derived from
  `grpc.ServiceDesc`, for example `POST /<proto-service>/<method>`

Unary HTTP calls still accept and return `application/protobuf`; streaming calls
are exposed as WebSocket binary frames containing protobuf messages. This means
the project already has an HTTP listener, but the API contract is still
protobuf/gRPC-shaped.

The final target is:

- no `.proto` IDL in this repo
- no generated `.pb.go` or `_grpc.pb.go`
- no `google.golang.org/grpc` dependency for the control plane
- no `google.golang.org/protobuf` dependency in runtime domain models
- plain Go structs as application contracts
- JSON over HTTP for request/response APIs
- WebSocket or SSE for long-lived streams

At the time of writing, the repo has 20 `.proto` files, 22 generated protobuf
or gRPC Go files, and more than 180 Go files with direct protobuf/gRPC/generated
type references. This is why the migration is intentionally staged.

This migration should be done in phases. Protobuf is currently not just a
transport format; it is also the in-memory domain model for configuration,
nodes, routes, inbounds, DNS, statistics, backup, Android preferences, node
serialization, and protocol registration. Removing it safely requires separating
transport migration from domain-model migration.

Implementation note:

- The management listener now registers explicit `/api/v1` HTTP routes instead
  of dispatching `application/grpc` or `grpc.ServiceDesc`-derived compatibility
  paths.
- Generated gRPC management adapters, `pkg/utils/grpc2http`, and the selectable
  `pkg/net/proxy/grpc` transport have been removed.
- `google.golang.org/grpc` is no longer a module dependency.
- The web UI now calls `/api/v1` through fetch/SSE, and no longer exposes the
  old `grpc` protocol/transport options.
- Protobuf-generated structs are still the domain model and persistence model;
  the next cleanup stage is replacing those with `pkg/schema` structs.

## 2. Current surface area

### 2.1 Generated API services

Current public management services come from `pkg/idl/api/*.proto`:

- `config_service`: load, save, info
- `lists`: list, list_page, get, save, remove, refresh, save_config
- `rules`: list, list_page, get, save, remove, change_priority, config,
  save_config, test, block_history
- `inbound`: list, list_page, get, save, remove, apply, platform_info
- `resolver`: list, list_page, get, save, remove, hosts, save_hosts, fakedns,
  save_fakedns, server, save_server
- `node`: now, use, get, save, remove, list, activates, close, latency
- `subscribe`: save, remove, update, get, remove_publish, list_publish,
  save_publish, publish
- `tag`: save, remove, list, list_page
- `connections`: conns, close_conn, total, notify, failed_history, all_history
- `tools`: get_interface, licenses, log, logv2
- `backup`: save, get, backup, restore

### 2.2 Non-management gRPC usage

There are two additional gRPC/protobuf surfaces outside the UI/control API:

- `pkg/net/proxy/grpc`: a transport implementation that creates a gRPC server
  and a bidirectional stream of `BytesValue` frames. This is not just an API
  endpoint; it is a user-selectable proxy transport.
- `pkg/node/subscribe.go`: `yuhaiin://` URLs contain base64 protobuf bytes, and
  remote publish uses a generated gRPC subscribe client.

Both must be migrated before protobuf/grpc dependencies can disappear.

### 2.3 Domain-model coupling

The following patterns currently couple business logic to generated protobuf
types:

- `*config.Setting`, `*node.Point`, `*api.*`, `*statistic.Connection`, and
  similar generated structs are used directly in control methods and stores.
- oneof helpers use protobuf reflection, for example protocol/transport
  dispatch in `pkg/register`.
- SQLite stores persist full protobuf JSON payloads in several tables.
- backup/restore and legacy import/export are built around protobuf structs.
- Android helpers call control objects directly with protobuf request/response
  values.
- tests and examples construct generated builder types.

Because of this, the removal plan must introduce Go-owned model packages before
generated code is deleted.

## 3. Goals and non-goals

### Goals

- Provide stable, documented HTTP endpoints with JSON request and response
  bodies.
- Replace gRPC server registration with explicit HTTP route registration.
- Replace generated API request/response types with plain Go structs.
- Replace generated config/node/statistic/backup/tools model types with plain
  Go structs.
- Replace protobuf oneof usage with explicit tagged Go structs/interfaces.
- Keep desktop and Android entry points on the same route and model layer.
- Preserve existing auth semantics during migration.
- Provide compatibility bridges while frontend, Android, and external clients
  migrate.
- Remove grpc/protobuf dependencies only after all runtime references are gone.

### Non-goals

- Redesigning the web UI.
- Changing proxy protocol behavior except for removing the gRPC transport.
- Changing SQLite schema shape unless a table still stores protobuf-specific
  payloads that must become JSON structs.
- Introducing OpenAPI/code generation as a required dependency for runtime.
  A generated OpenAPI document may be produced from tests or docs later, but the
  server should not depend on it.

## 4. Target architecture

### 4.1 Package layout

Add three explicit layers:

```text
pkg/schema/
  api/          // HTTP request/response DTOs
  config/       // runtime config structs
  node/         // node/protocol/subscribe/tag structs
  statistic/    // connection and flow structs
  tools/        // interfaces, licenses, logs
  backup/       // backup/restore structs

pkg/control/
  config/
  route/
  inbound/
  resolver/
  node/
  statistics/
  tools/
  backup/

pkg/httpapi/
  router.go
  respond.go
  errors.go
  sse.go
  websocket.go
  config.go
  route.go
  inbound.go
  resolver.go
  node.go
  statistics.go
  tools.go
  backup.go
```

The intended dependency direction is:

```text
cmd/* -> pkg/app -> pkg/httpapi -> pkg/control -> pkg/schema + domain packages
```

Domain packages may depend on `pkg/schema/*`, but must not depend on
`pkg/httpapi`. `pkg/httpapi` should only translate HTTP details into control
calls.

### 4.2 Control ports

Do not mirror generated gRPC service names as one large Go interface per proto
service. Define small control ports around the capability a handler actually
needs. The names should describe the control-plane concept, not the transport:
`Settings`, `Runtime`, `Connections`, `Traffic`, `ConnectionHistory`,
`Resolvers`, `Inbounds`, and so on.

Control ports must not mention HTTP, gRPC, protobuf wrappers, or generated
types.

Example shape:

```go
type Settings interface {
	Snapshot(ctx context.Context) (*config.Setting, error)
	Apply(ctx context.Context, next *config.Setting) error
}

type Runtime interface {
	BuildInfo(ctx context.Context) (*config.Info, error)
}

type Connections interface {
	Snapshot(ctx context.Context) (*api.ActiveConnections, error)
	Close(ctx context.Context, ids ...uint64) error
}

type Traffic interface {
	Totals(ctx context.Context) (*api.TrafficTotals, error)
	Watch(ctx context.Context) (<-chan api.TrafficEvent, error)
}

type ConnectionHistory interface {
	Failed(ctx context.Context) (*api.FailedConnections, error)
	All(ctx context.Context) (*api.ConnectionHistory, error)
}
```

This lets desktop, Android, tests, CLI helpers, and future HTTP handlers share
the same business logic without depending on transport code.

### 4.3 HTTP transport

Use only the standard `net/http` router unless a future route pattern makes that
too painful. The current code already uses Go's method-aware mux patterns such
as `GET /metrics`, so the new API can continue using `http.ServeMux`.

Default conventions:

- request/response body: JSON
- request content type: `application/json`
- response content type: `application/json; charset=utf-8`
- empty success response: `204 No Content`
- validation error: `400`
- auth failure: `401`
- not found: `404`
- conflict/state error: `409`
- cancellation/client disconnect: do not log as server error
- unexpected error: `500`

Response envelope should not be used for successful responses. HTTP status plus
the concrete JSON body is enough. Errors should use one consistent shape:

```json
{
  "error": {
    "code": "not_found",
    "message": "node not found"
  }
}
```

### 4.4 Streaming

Use SSE for server-to-client event streams:

- `GET /api/v1/connections/events`
- `GET /api/v1/tools/logs`
- `GET /api/v1/tools/logs/v2`

SSE is simpler for browser clients, reconnects cleanly, and fits the existing
server-streaming methods. Each event should include a stable `event` name and
JSON payload:

```text
event: total_flow
data: {"download":100,"upload":50,"counters":{"1":{"download":10,"upload":5}}}

event: connections_added
data: {"connections":[...]}

event: connections_removed
data: {"ids":[1,2]}
```

Use WebSocket only where bidirectional streaming is needed. For the current
management API, no existing generated service requires client-streaming or
bidirectional streaming. The gRPC proxy transport is the only bidirectional
streaming case and should be migrated separately.

### 4.5 Authentication and CORS

Keep Basic auth semantics in the first migration phase:

- desktop CLI `-u` and `-p` keep the same meaning
- Android can keep omitting auth because it binds to a local random port
- query `token` compatibility can stay during the compatibility window, but new
  clients should send `Authorization: Basic ...`

CORS should move from unconditional `*` toward a small allowlist later, but that
is not required to remove protobuf/gRPC.

## 5. HTTP endpoint design

Use `/api/v1` for the new JSON API. Existing protobuf-HTTP paths can remain
temporarily during migration.

Some collections have subresources such as `config`, `active`, `selected`, or
`platform-info`. Those names should be treated as reserved path segments. If a
user-defined resource can have the same name, handlers must either route the
reserved static path first or expose user resources under a less ambiguous path.

### 5.1 Config

| Current RPC | New endpoint |
| --- | --- |
| `config_service.load` | `GET /api/v1/config` |
| `config_service.save` | `PUT /api/v1/config` |
| `config_service.info` | `GET /api/v1/info` |

`PUT /api/v1/config` saves only the general setting slice currently handled by
`Chore.Save`: IPv6, default interface, log settings, system proxy, and advanced
config. Route, DNS, inbound, node, and backup domains stay on their own
endpoints.

### 5.2 Lists

| Current RPC | New endpoint |
| --- | --- |
| `lists.list` | `GET /api/v1/lists` |
| `lists.list_page` | `GET /api/v1/lists?page=&page_size=&query=` |
| `lists.get` | `GET /api/v1/lists/{name}` |
| `lists.save` | `PUT /api/v1/lists/{name}` |
| `lists.remove` | `DELETE /api/v1/lists/{name}` |
| `lists.refresh` | `POST /api/v1/lists:refresh` |
| `lists.save_config` | `PUT /api/v1/lists/config` |

The list object body should carry the same fields as the current bypass list
model. The URL name and body name must match when both are present.

### 5.3 Rules

| Current RPC | New endpoint |
| --- | --- |
| `rules.list` | `GET /api/v1/rules` |
| `rules.list_page` | `GET /api/v1/rules?page=&page_size=&query=` |
| `rules.get` | `GET /api/v1/rules/{name}/{index}` |
| `rules.save` | `PUT /api/v1/rules/{name}/{index}` |
| `rules.remove` | `DELETE /api/v1/rules/{name}/{index}` |
| `rules.change_priority` | `POST /api/v1/rules:change-priority` |
| `rules.config` | `GET /api/v1/rules/config` |
| `rules.save_config` | `PUT /api/v1/rules/config` |
| `rules.test` | `POST /api/v1/rules:test` |
| `rules.block_history` | `GET /api/v1/rules/block-history` |

For `change-priority`, keep the current operation enum values as lowercase
strings: `exchange`, `insert_before`, `insert_after`.

### 5.4 Inbounds

| Current RPC | New endpoint |
| --- | --- |
| `inbound.list` | `GET /api/v1/inbounds` |
| `inbound.list_page` | `GET /api/v1/inbounds?page=&page_size=&query=` |
| `inbound.get` | `GET /api/v1/inbounds/{name}` |
| `inbound.save` | `PUT /api/v1/inbounds/{name}` |
| `inbound.remove` | `DELETE /api/v1/inbounds/{name}` |
| `inbound.apply` | `POST /api/v1/inbounds:apply` |
| `inbound.platform_info` | `GET /api/v1/inbounds/platform-info` |

`apply` should keep accepting the current bulk enabled/DNS/sniff shape so the UI
can toggle inbounds without resending each full inbound definition.

### 5.5 Resolver

| Current RPC | New endpoint |
| --- | --- |
| `resolver.list` | `GET /api/v1/resolvers` |
| `resolver.list_page` | `GET /api/v1/resolvers?page=&page_size=&query=` |
| `resolver.get` | `GET /api/v1/resolvers/{name}` |
| `resolver.save` | `PUT /api/v1/resolvers/{name}` |
| `resolver.remove` | `DELETE /api/v1/resolvers/{name}` |
| `resolver.hosts` | `GET /api/v1/resolver/hosts` |
| `resolver.save_hosts` | `PUT /api/v1/resolver/hosts` |
| `resolver.fakedns` | `GET /api/v1/resolver/fakedns` |
| `resolver.save_fakedns` | `PUT /api/v1/resolver/fakedns` |
| `resolver.server` | `GET /api/v1/resolver/server` |
| `resolver.save_server` | `PUT /api/v1/resolver/server` |

For `server`, return a JSON object rather than a raw string:

```json
{"name":"bootstrap"}
```

### 5.6 Nodes

| Current RPC | New endpoint |
| --- | --- |
| `node.now` | `GET /api/v1/nodes/selected` |
| `node.use` | `POST /api/v1/nodes/{hash}:use` |
| `node.get` | `GET /api/v1/nodes/{hash}` |
| `node.save` | `POST /api/v1/nodes` for create, `PUT /api/v1/nodes/{hash}` for update |
| `node.remove` | `DELETE /api/v1/nodes/{hash}` |
| `node.list` | `GET /api/v1/nodes` |
| `node.activates` | `GET /api/v1/nodes/active` |
| `node.close` | `POST /api/v1/nodes/{hash}:close` |
| `node.latency` | `POST /api/v1/nodes:latency` |

`POST /api/v1/nodes` creates a node and may generate a hash. Updating an
existing node uses `PUT /api/v1/nodes/{hash}` and should reject a body hash that
conflicts with the path hash.

### 5.7 Subscribe

| Current RPC | New endpoint |
| --- | --- |
| `subscribe.get` | `GET /api/v1/subscriptions` |
| `subscribe.save` | `PUT /api/v1/subscriptions` |
| `subscribe.remove` | `DELETE /api/v1/subscriptions` |
| `subscribe.update` | `POST /api/v1/subscriptions:update` |
| `subscribe.list_publish` | `GET /api/v1/publishes` |
| `subscribe.save_publish` | `PUT /api/v1/publishes/{name}` |
| `subscribe.remove_publish` | `DELETE /api/v1/publishes/{name}` |
| `subscribe.publish` | `POST /api/v1/publishes/{name}:resolve` |

`DELETE /api/v1/subscriptions` and `POST /api/v1/subscriptions:update` accept:

```json
{"names":["a","b"]}
```

`PUT /api/v1/subscriptions` accepts:

```json
{"links":[...]}
```

### 5.8 Tags

| Current RPC | New endpoint |
| --- | --- |
| `tag.list` | `GET /api/v1/tags` |
| `tag.list_page` | `GET /api/v1/tags?page=&page_size=&query=` |
| `tag.save` | `PUT /api/v1/tags/{tag}` |
| `tag.remove` | `DELETE /api/v1/tags/{tag}` |

Body for save:

```json
{"type":"mirror","hash":"node-hash"}
```

### 5.9 Connections and statistics

| Current RPC | New endpoint |
| --- | --- |
| `connections.conns` | `GET /api/v1/connections` |
| `connections.close_conn` | `POST /api/v1/connections:close` |
| `connections.total` | `GET /api/v1/connections/total` |
| `connections.notify` | `GET /api/v1/connections/events` |
| `connections.failed_history` | `GET /api/v1/connections/failed-history` |
| `connections.all_history` | `GET /api/v1/connections/history` |

`connections.events` should be SSE.

### 5.10 Tools

| Current RPC | New endpoint |
| --- | --- |
| `tools.get_interface` | `GET /api/v1/tools/interfaces` |
| `tools.licenses` | `GET /api/v1/tools/licenses` |
| `tools.log` | `GET /api/v1/tools/logs` |
| `tools.logv2` | `GET /api/v1/tools/logs/v2` |

`logs` and `logs/v2` should be SSE. If the current UI expects WebSocket, keep a
temporary WebSocket route while moving clients to SSE.

### 5.11 Backup

| Current RPC | New endpoint |
| --- | --- |
| `backup.get` | `GET /api/v1/backup/config` |
| `backup.save` | `PUT /api/v1/backup/config` |
| `backup.backup` | `POST /api/v1/backup:run` |
| `backup.restore` | `POST /api/v1/backup:restore` |

Long-running backup/restore should remain synchronous initially to match current
behavior. A later improvement can return a job ID.

## 6. Plain Go schema design

### 6.1 JSON field names

Preserve existing protobuf `json_name` values as Go JSON tags where possible.
This limits frontend and Android churn.

Example:

```go
type PageRequest struct {
	Page     uint32 `json:"page"`
	PageSize uint32 `json:"page_size"`
	Query    string `json:"query"`
}
```

### 6.2 Optional fields

Generated opaque protobuf currently distinguishes unset from zero for some
fields. Plain structs need explicit rules:

- Required fields use values.
- Optional scalar fields that need tri-state behavior use pointers.
- Internal normalized runtime config should avoid pointers unless unset has
  actual business meaning.
- HTTP handlers validate required fields before calling services.

### 6.3 Enums

Use string enums in JSON and typed string constants in Go:

```go
type RuleMode string

const (
	RuleModeDirect RuleMode = "direct"
	RuleModeProxy  RuleMode = "proxy"
	RuleModeBlock  RuleMode = "block"
)
```

This avoids protobuf numeric enum compatibility problems and makes HTTP payloads
readable.

### 6.4 Replacing oneof

Replace protobuf oneof with tagged structs. The tagged shape should be stable in
JSON and simple to switch over in Go.

Recommended shape for protocol stacks:

```json
{
  "protocols": [
    {
      "type": "websocket",
      "websocket": {
        "host": "example.com",
        "path": "/ws"
      }
    },
    {
      "type": "vmess",
      "vmess": {
        "uuid": "..."
      }
    }
  ]
}
```

Recommended Go shape:

```go
type Protocol struct {
	Type ProtocolType `json:"type"`

	Socks5             *Socks5             `json:"socks5,omitempty"`
	HTTP               *HTTP               `json:"http,omitempty"`
	Shadowsocks        *Shadowsocks        `json:"shadowsocks,omitempty"`
		WebSocket          *WebSocket          `json:"websocket,omitempty"`
		NetworkSplit       *NetworkSplit       `json:"network_split,omitempty"`
		CloudflareWarpMASQ *CloudflareWarpMASQ `json:"cloudflare_warp_masque,omitempty"`
	}
```

The old `grpc` protocol/transport type has been removed instead of kept as a
new-schema migration case. Legacy configs that still contain that transport need
a one-time migration or a validation error before the protobuf model is deleted.

### 6.5 Type dispatch

`pkg/register` should stop using `protoreflect.FullName`. Replace registration
keys with typed string identifiers:

```go
type ProtocolType string

type WrapProxy[T any] func(T, netapi.Proxy) (netapi.Proxy, error)

var pointRegistry map[schema.ProtocolType]func(schema.Protocol, netapi.Proxy) (netapi.Proxy, error)
```

Each proxy package registers with an explicit type constant:

```go
register.RegisterPoint(schema.ProtocolTypeWebSocket, func(c schema.WebSocket, p netapi.Proxy) (netapi.Proxy, error) {
	return NewClient(c, p)
})
```

Inbound network/transport/protocol registries should follow the same pattern.

## 7. Compatibility strategy

### 7.1 API compatibility window

For at least one release window:

- keep current generated gRPC services
- keep current protobuf-HTTP compatibility paths
- add `/api/v1` JSON routes
- update web UI and Android to use `/api/v1`
- add logs warning when old protobuf routes are used, gated to avoid spam

After clients are migrated:

- delete generated gRPC service registration
- delete `pkg/utils/grpc2http`
- delete management API proto files and generated API files

### 7.2 Data compatibility

Existing users may have protobuf JSON payloads in SQLite. Migration should be
online and idempotent:

1. read existing protobuf JSON into generated types while compatibility code is
   still present
2. convert generated types into plain Go structs
3. write the new JSON payload shape with a schema version marker
4. on restart, prefer the new JSON shape

Do not delete protobuf decode code until every persisted payload has a
non-protobuf reader.

### 7.3 `yuhaiin://` compatibility

Current `yuhaiin://` payload is base64 protobuf bytes. Introduce a versioned JSON
URL format:

```text
yuhaiin+json://<base64url-json>
```

Payload:

```json
{
  "version": 1,
  "name": "default",
  "points": [...]
}
```

Migration behavior:

- new publish/share creates `yuhaiin+json://`
- importer supports both old `yuhaiin://` protobuf and new `yuhaiin+json://`
  during compatibility
- once protobuf is removed, either keep a tiny legacy decoder in a separate
  migration package or declare old links unsupported in a major release note

### 7.4 Remote publish compatibility

Replace generated gRPC remote publish with an HTTP endpoint:

```text
POST /api/v1/publishes/{name}:resolve
```

Request:

```json
{"path":"/optional/path","password":"optional-password"}
```

Response:

```json
{"points":[...]}
```

During compatibility, remote subscription fetch should try HTTP first when the
remote advertises a JSON publish URL, and fall back to gRPC for old remotes.

## 8. Frontend migration

The frontend migration should be planned as a first-class part of this work, not
as a final cleanup after the backend changes. This repo embeds the released web
UI through `github.com/yuhaiin/yuhaiin.github.io`, and local development can use
`EXTERNAL_WEB`, so backend and frontend can migrate independently but must keep
one compatibility window.

### 8.1 Current frontend contract

The current web UI is coupled to the protobuf-shaped HTTP compatibility layer:

- unary calls use generated service/method paths, not resource paths
- request and response bodies are protobuf bytes
- server streams use WebSocket binary protobuf frames
- errors are plain HTTP error text from the compatibility wrapper
- auth is Basic auth, with the current token query compatibility for some
  callers

The new frontend contract should be JSON and event based:

- normal operations call `/api/v1/*` with JSON bodies
- server-push flows use SSE and JSON event payloads
- errors use the shared JSON error object
- frontend code should not know about protobuf service names, generated method
  names, or binary protobuf payloads

### 8.2 Client package shape

Create one small frontend API package and keep raw `fetch` calls out of pages
and components. Suggested shape:

```text
src/api/
  client.ts       // base URL, auth, JSON decode, error mapping
  stream.ts       // EventSource/SSE helpers
  legacy.ts       // temporary protobuf HTTP calls during migration
  settings.ts
  connections.ts
  nodes.ts
  rules.ts
  lists.ts
  inbounds.ts
  resolvers.ts
  subscriptions.ts
  tags.ts
  tools.ts
  backup.ts
```

The package should expose domain functions, not transport details:

```ts
export async function loadSettings(signal?: AbortSignal): Promise<Setting>
export async function applySettings(next: Setting, signal?: AbortSignal): Promise<void>
export async function connectionTotals(signal?: AbortSignal): Promise<TrafficTotals>
export function watchTraffic(onEvent: (event: TrafficEvent) => void): Closeable
```

During the compatibility window, `legacy.ts` may keep the old protobuf path
available for endpoints that have not moved yet. The rest of the UI should not
import `legacy.ts` directly; domain API modules own the fallback decision.

### 8.3 TypeScript types

TypeScript types should mirror `pkg/schema` JSON, not protobuf names. There are
two acceptable options:

- maintain hand-written TypeScript interfaces beside the API client while the
  schema is still moving
- generate TypeScript types from a checked-in JSON schema/OpenAPI snapshot after
  `/api/v1` stabilizes

Do not generate frontend types from `.proto` during the migration. That would
keep protobuf as the source of truth and make the final removal harder.

For tagged protocol structs, use discriminated unions:

```ts
type Protocol =
  | { type: "websocket"; websocket: WebSocketProtocol }
  | { type: "vmess"; vmess: VMessProtocol }
  | { type: "grpc"; grpc: GrpcProtocol; deprecated?: true }
```

The UI should preserve unknown or deprecated protocol entries when editing a
node unless the user explicitly changes that protocol. This prevents the first
JSON UI release from destroying legacy configs it cannot fully edit yet.

### 8.4 Streaming migration

Replace protobuf WebSocket streams with SSE where the server only pushes data:

- `connections.notify` becomes `GET /api/v1/connections/events`
- `tools.log` becomes `GET /api/v1/tools/logs`
- `tools.logv2` becomes `GET /api/v1/tools/logs/v2`

The frontend stream helper should:

- parse `event:` names into typed events
- treat disconnect as a recoverable state
- expose an explicit close function for page unmount
- avoid overlapping reconnect loops
- fall back to the old WebSocket stream only while that endpoint has not moved

SSE events should update the same local stores/hooks currently fed by protobuf
stream messages, so UI rendering can migrate separately from transport.

### 8.5 Error and loading behavior

The API client should normalize backend errors into one frontend error type:

```ts
type ApiError = {
  status: number
  code: string
  message: string
}
```

Pages should stop parsing raw text errors from the old compatibility wrapper
once they use `/api/v1`. Loading state should be owned by the domain hook or
store using the API client, not by low-level transport helpers.

### 8.6 Frontend rollout order

Migrate the frontend endpoint by endpoint while both old and new backend routes
exist:

1. add the shared JSON client and typed error handling
2. migrate read-only endpoints first: info, traffic totals, current
   connections, lists/rules/inbounds/resolvers list pages
3. migrate SSE streams: connection events and logs
4. migrate simple mutations: close connection, select node, remove tag/remove
   list/remove inbound
5. migrate complex editors: node, inbound, rule, resolver, backup restore
6. delete protobuf client code only after the UI has no imports of the legacy
   transport package

The backend should log old protobuf route usage during this period. That gives a
simple way to catch UI pages or Android screens that still call the old paths.

### 8.7 Frontend verification

Before removing protobuf routes, verify the frontend with:

- frontend build and lint
- mocked API tests for the JSON client and SSE parser
- one local integration run using `EXTERNAL_WEB` against the backend binary
- browser checks for connection list updates, log streaming, settings save,
  node save, rule priority changes, resolver edits, inbound apply, backup
  trigger, and restore validation
- a negative-path check that JSON error bodies render cleanly

## 9. gRPC proxy transport replacement

`pkg/net/proxy/grpc` was a separate transport feature and did block dependency
removal. It has now been deleted together with the UI options and IDL fields.

Recommended replacement:

- add a WebSocket stream transport, or reuse/enhance the existing websocket
  transport if it already covers the same deployment needs
- add an HTTP/2 stream transport only if users need gRPC-like HTTP/2 behavior
  without protobuf/gRPC
- provide config migration from legacy `grpc` configs to `websocket` or `http2`
  where possible

The existing gRPC transport carries opaque bytes and does not use protobuf
schema beyond `BytesValue`; WebSocket binary frames are therefore the closest
replacement.

## 10. Migration phases

### Phase 0: inventory and guardrails

- Add tests that enumerate all current HTTP/gRPC methods and assert the new
  `/api/v1` route table covers them.
- Add `rg`-style CI guard scripts or tests for forbidden imports once each
  phase is complete.
- Capture current protobuf JSON samples for config, node, inbound, resolver,
  route, backup, and statistics payloads.
- Inventory frontend protobuf call sites and stream consumers in the web UI.

Exit criteria:

- route coverage list is complete
- representative legacy payload fixtures exist
- frontend call-site inventory exists

### Phase 1: HTTP JSON route layer

- Add `pkg/httpapi` helpers for JSON decode/encode, typed errors, auth wrapper,
  SSE, and request path helpers.
- Add `/api/v1` handlers backed by existing control objects.
- In this phase handlers may convert between JSON DTOs and generated protobuf
  structs internally.
- Keep generated protobuf API message types as temporary handler DTOs.
- Add the frontend JSON client and migrate one read-only page or hook.

Exit criteria:

- web/Android can call JSON routes for at least config/info/connections total
- existing protobuf/gRPC tests still pass
- new HTTP handler tests cover status codes and JSON error shape
- frontend build still passes with old and new clients side by side

### Phase 2: split control ports from generated API interfaces

- Introduce handwritten control ports.
- Move business logic out of generated `api.*Server` methods into control
  methods that use plain signatures.
- Keep generated gRPC servers as adapters that call the new control methods.
- Keep HTTP handlers as adapters that call the same control methods.

Exit criteria:

- no domain package needs to embed `api.Unimplemented*Server`
- generated server implementations are thin compatibility adapters
- Android direct control calls use handwritten interfaces

### Phase 3: introduce plain schema structs

- Add `pkg/schema` packages.
- Convert API DTOs first, then config/node/statistic/backup domain models.
- Add generated-proto-to-schema and schema-to-generated-proto conversion only in
  migration/compat packages.
- Replace protobuf reflection dispatch in `pkg/register` with string typed
  registries.

Exit criteria:

- new business logic depends on `pkg/schema`, not `pkg/protos`
- all oneof runtime dispatch uses explicit type strings
- HTTP JSON handlers no longer construct protobuf messages for normal paths

### Phase 4: persistence migration

- Update SQLite JSON payload columns to store schema JSON instead of protojson.
- Add idempotent migrations for legacy protojson rows.
- Migrate Android preference/config byte payloads away from protobuf.
- Update backup snapshot format to schema JSON.

Exit criteria:

- fresh install writes no protobuf payloads
- upgrade from legacy config succeeds
- backup/restore round trip uses only schema JSON

### Phase 5: client migration and compatibility removal

- Finish web UI migration to `/api/v1` and delete frontend protobuf client code.
- Update Android app integration to `/api/v1` or direct control calls.
- Update examples and docs.
- Remove generated gRPC management adapters and `pkg/utils/grpc2http`.
- Remove API `.proto` files and generated API `.pb.go`/`_grpc.pb.go`.

Exit criteria:

- no runtime code imports `pkg/protos/api`
- no runtime code imports `google.golang.org/grpc` for management APIs
- no HTTP route depends on `grpc.ServiceDesc`
- frontend has no protobuf transport imports and no old generated service paths

### Phase 6: remove remaining protobuf/grpc runtime

- Replace `pkg/net/proxy/grpc`.
- Replace old `yuhaiin://` protobuf share format or isolate legacy decode.
- Remove remaining generated config/node/statistic/tools/backup models.
- Remove `pkg/idl`, `pkg/protos`, and protobuf dependencies.
- Regenerate license files.

Exit criteria:

- `rg "google.golang.org/grpc|google.golang.org/protobuf|pkg/protos|pkg/idl"`
  has no runtime hits
- `go mod tidy` removes grpc/protobuf
- tests pass with `GOEXPERIMENT=jsonv2,greenteagc`

## 11. Testing plan

### Unit tests

- JSON decode/encode and error shape tests for `pkg/httpapi`.
- Control interface tests using fake stores.
- Schema validation tests for required fields and enum values.
- Registry dispatch tests for every protocol/transport type.
- Legacy conversion fixture tests for config, node, resolver, inbound, rules,
  backup, and statistics payloads.
- Frontend API client tests for JSON request/response handling and normalized
  errors.
- Frontend SSE parser tests for connection and log events.

### Integration tests

- Start `app.Start` with an HTTP mux and call `/api/v1` endpoints through
  `httptest`.
- Verify auth success/failure for JSON endpoints.
- Verify SSE event stream emits current `connections.notify` event types.
- Verify Android start path still serves the same route table without a gRPC
  server.
- Verify upgrade from legacy SQLite state to schema JSON is idempotent.
- Run the frontend against a local backend through `EXTERNAL_WEB` before
  removing old routes.

### Regression tests

- Existing route/list/rule/node/resolver/inbound/statistics behavior should be
  covered before deleting generated adapters.
- For network-dependent tests, keep using targeted skips for non-hermetic cases
  rather than treating remote network availability as a unit-test requirement.

## 12. Rollback strategy

Until Phase 5, rollback is straightforward because old protobuf/gRPC routes stay
registered. Each phase should avoid deleting old code until the next replacement
is tested.

After Phase 5:

- keep one release branch with protobuf/gRPC compatibility for emergency fixes
- keep legacy SQLite conversion tests permanently
- keep a command or debug endpoint that reports the detected config model
  version

After Phase 6:

- rollback across the protobuf removal boundary requires restoring the previous
  release binary, so backup/restore compatibility must be validated before
  release

## 13. Open decisions

- Whether to keep `yuhaiin://` legacy protobuf import forever through a small
  isolated decoder, or remove it in a major release.
- Whether remote publish should support unauthenticated local-network access
  exactly as today, or require Basic auth/token by default.
- Whether the gRPC proxy transport should migrate to existing websocket
  transport, a new HTTP/2 stream transport, or both.
- Whether to generate an OpenAPI document from handwritten route tests after
  `/api/v1` stabilizes.
- Whether frontend TypeScript types should stay hand-written during the whole
  migration or be generated from a JSON schema/OpenAPI snapshot once stable.

## 14. First implementation slice

The lowest-risk first slice is:

1. Add `pkg/httpapi` with JSON helpers, typed errors, and auth wrapping.
2. Add `GET /api/v1/info`.
3. Add `GET /api/v1/connections/total`.
4. Add `GET /api/v1/connections/events` as SSE.
5. Add route coverage tests proving old `connections.notify` has an HTTP/SSE
   equivalent.
6. Add the frontend JSON client and migrate the info/traffic-total read path.

This slice exercises normal JSON, auth, a read-only service, and a streaming
endpoint without touching the hardest config/node oneof model migration yet.
