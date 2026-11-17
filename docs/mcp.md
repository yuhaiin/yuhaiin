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
permissions and secret redaction. Only tools permitted by both the user's current
permissions and the granted scopes are listed, and each call is authorized again
when it runs.

| Tool | Operation | Permission | Kind |
| --- | --- | --- | --- |
| `get_system_info` | `info` | `settings:read` | read |
| `get_settings` | `settings.get` | `settings:read` | read |
| `list_nodes` | `nodes.get` | `nodes:read` | read |
| `get_selected_node` | `nodes.selected` | `nodes:read` | read |
| `list_inbounds` | `inbounds.get` | `inbounds:read` | read |
| `get_connections` | `connections` | `connections:read` | read |
| `get_traffic` | `connections.total` | `connections:read` | read |
| `get_routes` | `route.rules.get` | `routes:read` | read |
| `get_resolvers` | `resolvers.get` | `resolver:read` | read |
| `get_system_network` | `systemNetwork.status` | `settings:read` | read |
| `select_node` | `nodes.select` | `nodes:write` | changes routing |
| `close_connections` | `connections.close` | `connections:write` | destructive |
| `update_subscription` | `subscriptions.update` | `nodes:write` | contacts subscription servers |

Every tool has an explicit, closed JSON Schema. Unknown arguments are rejected.
Tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
`openWorldHint`) describe the tools for clients, but they are hints, not
security: the server authorizes every call. Results are always redacted, and
MCP clients can never obtain the secret-reveal capability. Tools that change
configuration wholesale (settings, nodes, routes, inbounds) are deliberately not
exposed yet.

Operation errors are returned as tool results with `isError: true` and the same
error code as the HTTP API, for example `permission_denied: …` or
`unavailable: …`.

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

Add an entry to `builtinTools` in `pkg/management/mcpserver/tools.go` naming an
existing `httpapi` operation. Define its schema and argument conversion to the
operation's request DTO, and set its annotations. The permission comes from the
operation's entry in `pkg/httpapi/permissions.go`. The MCP resource's
`scopes_supported` then includes it automatically.
