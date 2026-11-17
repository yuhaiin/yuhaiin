# MCP server

Yuhaiin serves the [Model Context Protocol](https://modelcontextprotocol.io) at
`ISSUER/mcp` over Streamable HTTP, using the official
[Go SDK](https://github.com/modelcontextprotocol/go-sdk). MCP is one protected
resource of the [Yuhaiin OAuth Authorization Server](oauth.md). Authentication,
authorization and token management are shared with the management API; the MCP
package contains only the protocol adapter and its tools.

## Enabling

1. Make the controller reachable over HTTPS at a stable public origin, for
   example through managed certificates, a reverse proxy or Cloudflare Tunnel.
2. In **Account & security → OAuth authorization server**, set the issuer to
   that origin, enable the server and leave the `mcp` resource enabled.
3. Give users who should connect MCP clients the `mcp:connect` permission. The
   built-in `admin` and `read-only` roles include it. Custom roles can add it.

The **MCP** panel in the same section shows the endpoint URL, the issuer, the
protected resource metadata URL, the supported scopes and the authorized MCP
clients.

## Connecting a client

MCP clients that implement the MCP authorization specification need only the
URL:

```text
https://yuhaiin.example.com/mcp
```

The client receives `401` with
`WWW-Authenticate: Bearer resource_metadata="https://yuhaiin.example.com/.well-known/oauth-protected-resource/mcp"`,
discovers the Authorization Server, registers itself, opens the Yuhaiin consent
page in a browser, and exchanges the code with PKCE and
`resource=https://yuhaiin.example.com/mcp`.

- **Claude (desktop and web):** *Settings → Connectors → Add custom connector*,
  then enter the MCP URL. Claude's servers must be able to reach the URL.
- **Claude Code:** `claude mcp add --transport http yuhaiin https://yuhaiin.example.com/mcp`,
  then run `/mcp` inside Claude Code to sign in.
- **Other clients:** configure a "Streamable HTTP" or "HTTP" server with the URL.
  Clients without OAuth support cannot connect, because API tokens and sessions
  are not accepted at `/mcp`.

On the consent page, choose which tools the client may use by selecting their
permissions. `mcp:connect` is required for any connection.

## Tools

The tools run the same operations as the HTTP API, with the same DTOs,
permissions, validation, secret handling and configuration audit. Only tools
permitted by both the user's current permissions and the granted scopes are
listed, and each call is authorized again when it runs.

### Status

| Tool | Operation | Permission |
| --- | --- | --- |
| `get_system_info` | `info` | `settings:read` |
| `get_settings` | `settings.get` | `settings:read` |
| `get_system_network` | `systemNetwork.status` | `settings:read` |
| `list_nodes`, `get_node`, `get_selected_node` | `nodes.get`, `node.get`, `nodes.selected` | `nodes:read` |
| `get_connections`, `get_traffic` | `connections`, `connections.total` | `connections:read` |
| `select_node` | `nodes.select` | `nodes:write` |
| `close_connections` | `connections.close` | `connections:write` |
| `update_subscription` | `subscriptions.update` | `nodes:write` |

### Configuration: add, change, delete and test

| Area | Tools | Permission |
| --- | --- | --- |
| Nodes | `preview_node_import`, `import_nodes` (share links such as `ss://`, `vmess://`, `trojan://`, or a subscription body), `save_node`, `delete_node`, `test_node_latency` | `nodes:write` |
| Inbounds | `get_inbound`, `get_inbound_capabilities`, `get_inbound_status`, `list_inbounds` | `inbounds:read` |
| | `save_inbound`, `delete_inbound` | `inbounds:write` |
| HTTP Gateway | `get_gateway`, `get_gateway_status` | `gateway:read` |
| | `save_gateway` | `gateway:write` |
| | `test_gateway` | `diagnostics:run` |
| Route lists | `list_route_lists`, `get_route_list` | `routes:read` |
| | `create_route_list`, `update_route_list`, `delete_route_list` | `routes:write` |
| Rules | `get_routes`, `get_route_rule`, `test_route`, `get_route_activation` | `routes:read` |
| | `create_route_rule`, `update_route_rule`, `delete_route_rule`, `apply_routes` | `routes:write` |
| DNS | `get_resolvers`, `get_resolver` | `resolver:read` |
| | `save_resolver`, `delete_resolver`, `test_resolver` | `resolver:write` |
| Hosts | `list_hosts` | `resolver:read` |
| | `add_host`, `update_host`, `delete_host` | `resolver:write` |

Objects that contain credentials, such as a node password or inbound users, can
only be saved with `secrets:manage`, exactly as in the Web UI. The MCP resource
therefore offers that scope as well.

A typical session: `import_nodes` with a share link, `test_node_latency` on the
new node, `create_route_list` and `create_route_rule` to send some hosts
through it, `apply_routes`, and `test_route` to confirm the decision.

#### Schemas and arguments

The input schema of every configuration tool is generated from the HTTP API
request type (`pkg/management/mcpserver/schema.go`), so it cannot drift from the
API. Named types become `$defs`, which also covers recursive types such as
protocol chains and rule expressions. Tagged unions list their allowed `type`
values. Every object is closed, and arguments are decoded strictly into the
request type, so unknown members are rejected before the operation runs. The
operation then applies its usual validation.

Read tools return the same shape the save tools accept. To change something,
read it, modify it and save it back. Secrets are always redacted in results.
A redacted value sent back unchanged keeps the stored secret, and MCP clients
can never obtain the secret-reveal capability. Saving a node, inbound or
resolver without an `id` creates it with a new UUID. `save_gateway` replaces the
whole Gateway workspace and needs the revision from `get_gateway`.

Tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
`openWorldHint`) describe the tools for clients, but they are hints, not
security: the server authorizes every call. Operation errors are returned as
tool results with `isError: true` and the same error code as the HTTP API, for
example `permission_denied: …`, `conflict: …` or `bad_request: …`.

## Sessions, revocation and cancellation

The server is stateless: every MCP POST carries the bearer token and passes
through the management gate on its own, so revocation, a disabled user, a
permission change or a disabled MCP resource apply to the next request.
Responses use `application/json`, and the standalone SSE stream (`GET /mcp`) is
not offered. When a client disconnects or cancels a request, the operation's
context is cancelled.

The SDK's localhost Host-header check is disabled because it would reject every
reverse proxy and tunnel. DNS rebinding is prevented by the management gate,
which rejects untrusted `Origin` headers and requires an OAuth bearer token on
every request.

## Adding a tool

Add an entry to `statusTools` (`tools.go`) or `configurationTools`
(`tools_config.go`) naming an existing `httpapi` operation. For a
configuration operation, `dtoTool[RequestType]` derives the schema and strict
argument decoding from the request type; otherwise define the schema and the
argument conversion explicitly. Set the tool kind so that its annotations are
correct. The permission comes from the
operation's entry in `pkg/httpapi/permissions.go`. The MCP resource's
`scopes_supported` then includes it automatically.
