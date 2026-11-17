# OAuth 2.1 Authorization Server

Yuhaiin includes an OAuth 2.1 Authorization Server for its own management
interfaces. OAuth is a shared management identity feature, not part of MCP: the
HTTP management API, the MCP server and any later interface are separate
*protected resources* of one Authorization Server. They share one credential
store, one `Principal` and one permission registry.

This is unrelated to [GitHub, Google and OIDC sign-in](MANAGEMENT_AUTH.md#github-and-google-oauth).
With those, Yuhaiin is an OAuth *client* of an external identity provider, and
they are simply other ways for a user to sign in. Here Yuhaiin is the
*provider*: it issues access tokens to applications that a signed-in user has
authorized.

See also: [OAuth clients and the HTTP API](oauth-clients.md) and
[MCP server](mcp.md).

## Architecture

```text
            OAuth clients (MCP clients, external apps, automation)
                                  │
            ┌─────────────────────┴─────────────────────┐
            │   Authorization Server (pkg/management/auth)  │
            │   metadata · authorize · consent · token ·    │
            │   revoke · register                          │
            └─────────────────────┬─────────────────────┘
                                  │ hashes only
            ┌─────────────────────┴─────────────────────┐
            │ management.db: users, roles, management_credentials │
            │ (session/token/oauth_access/oauth_refresh),        │
            │ oauth clients, grants, authorization codes          │
            └─────────────────────┬─────────────────────┘
                                  │
                       Server.Wrap (one gate for every request):
          HTTPS/loopback · trusted Origin · credential → Principal ·
          route permission · secret redaction · audit · watchdog
                                  │
              ┌───────────────────┴───────────────────┐
     Management API resource              MCP resource (pkg/management/mcpserver)
     https://HOST/api                     https://HOST/mcp
     /api/, /debug/, /metrics             official MCP Go SDK, Streamable HTTP
              │                                       │
              └──── httpapi.Operations (same handlers, DTOs, permissions) ───┘
                                  │
                             Yuhaiin core
```

| Package | Responsibility |
| --- | --- |
| `pkg/management/permission` | The only permission registry. A permission ID is also the OAuth scope ID. `Delegable` marks which ones an OAuth client may receive. |
| `pkg/management/oauth` | Storage-free protocol pieces: the resource registry, PKCE S256, redirect URI and issuer validation, resource indicators, scope parsing, RFC 8414/9728 documents, errors and `WWW-Authenticate` challenges. |
| `pkg/management/auth` | The Authorization Server itself (`AuthorizationServer`), its endpoints, the token validator, consent and administration APIs, and the integration into `Server.Wrap`. |
| `pkg/management/mcpserver` | The MCP protocol adapter only. It registers itself as a resource and runs `httpapi.Operations`. It has no users, tokens or permissions of its own. |
| `pkg/httpapi` | `Operations` runs each v2 RPC action in process, without HTTP, with the same request/response types, permission table and secret redaction as the HTTP routes. |

### Protected resources

A resource is an `oauth.Resource`: an ID, a display name, a path appended to the
issuer to form its canonical URI, the request path prefixes it serves, its
scopes, an optional required scope, and whether it also accepts sessions and API
tokens. The process registers:

| ID | Canonical URI | Paths | Scopes | Other credentials |
| --- | --- | --- | --- | --- |
| `api` | `ISSUER/api` | `/api/`, `/debug/`, `/metrics` | every delegable permission except `mcp:connect` | sessions and API tokens keep working |
| `mcp` | `ISSUER/mcp` | `/mcp` | `mcp:connect` (required), `secrets:manage` and the permissions of the MCP tools | OAuth access tokens only |

A new resource is one more `Registry.Register` call next to these two. The
Authorization Server, its metadata, consent page and validator need no change.

Resource URIs come only from the issuer an administrator configured. They are
never built from the `Host` header or from `Forwarded`/`X-Forwarded-*` headers.
Behind Cloudflare Tunnel or a reverse proxy, set the issuer to the public origin
(for example `https://yuhaiin.example.com`).

## Configuration

**Account & security → OAuth authorization server** (requires `security:write`
and a session):

| Setting | Default | Meaning |
| --- | --- | --- |
| Enabled | off | While off, every OAuth endpoint, resource metadata document and `/mcp` answer 404, and every issued token is rejected. |
| Issuer | empty | The public origin, `https://host[:port]` with no path. `http://` is allowed only for loopback hosts. Changing it invalidates every token, because every resource URI changes with it. |
| Dynamic client registration | on | Open RFC 7591 registration for MCP clients. |
| Disabled resources | none | For example, disable `mcp` while keeping OAuth for the API. Tokens for a disabled resource stop working. |
| Access token lifetime | 900 s | 300–3600 s. |
| Refresh token lifetime | 14 days | Idle limit: each refresh issues a new refresh token valid for this long, but never beyond the grant. |
| Grant lifetime | 90 days | Absolute limit of an authorization, after which the user has to consent again. |

The same settings are available at `GET/PUT /api/v2/auth/oauth-server/settings`
with optimistic revision checks.

## Flows

### Authorization code with PKCE

1. The client reads `/.well-known/oauth-authorization-server`, and for MCP also
   the RFC 9728 document named in the `WWW-Authenticate` challenge.
2. The browser opens `/oauth/authorize` with `response_type=code`, `client_id`,
   `redirect_uri`, `code_challenge` and `code_challenge_method=S256`, `resource`,
   `scope` and `state`.
3. Yuhaiin validates the client, the exact redirect URI, PKCE, the resource and
   the scopes. Errors that happen before the redirect URI is proven are shown on
   a Yuhaiin error page and never redirect. Valid requests are kept server-side
   for 10 minutes and the browser goes to the Web UI consent page
   (`/#/oauth/consent/<id>`).
4. If needed, the user signs in with any existing method: password, passkey,
   GitHub, Google or OIDC. Signing in never approves anything by itself.
5. The consent page shows the application, its client ID and type, whether it
   registered itself, the redirect origin, the resource, every scope with its
   description and read/write classification, scopes the user does not hold,
   and token and grant lifetimes. The user ticks the scopes to grant, then
   allows or denies.
6. On approval, Yuhaiin issues a single-use authorization code valid for five
   minutes and redirects to `redirect_uri?code=…&state=…&iss=ISSUER` (RFC 9207).
7. The client exchanges the code at `/oauth/token` with the `code_verifier`.

### Tokens

All tokens are opaque 256-bit random strings with a type prefix:

| Prefix | Credential | Stored as |
| --- | --- | --- |
| `yu_` | API token (unchanged) | SHA-256 verifier in `management_credentials`, kind `token` |
| `yuat_` | OAuth access token | SHA-256 verifier, kind `oauth_access`, bound to a grant |
| `yurt_` | OAuth refresh token | SHA-256 verifier, kind `oauth_refresh`, bound to a grant |
| `yuac_` | Authorization code | SHA-256 verifier in `management_oauth_codes` |
| `yucs_` | Client secret | SHA-256 verifier in `management_oauth_clients` |

The prefix decides how a Bearer credential is validated. An API token is never
looked up as an OAuth token or the other way round, and a refresh token is never
accepted as an access token.

A grant is one user's authorization of one client for one resource with a fixed
set of scopes. A grant is also the refresh token family. Several grants for the
same user and client are managed independently.

## Security model

### Scopes and permissions

There is one permission registry. Scope `nodes:read` *is* permission
`nodes:read`. Permissions that mint credentials or change trust boundaries stay
with interactive sessions and API tokens and are never delegable: `users:manage`,
`tokens:manage`, `tokens:own`, `roles:write`, `security:write`, `secrets:read`
and `system:execute`.

An access token's effective permissions are recomputed on every request:

```text
granted scopes ∩ the user's current effective permissions
               ∩ the resource's scopes ∩ the client's allowed scopes
```

At consent, the granted scopes are themselves the intersection of the request,
the client's allowed scopes, the resource's scopes, the user's current
permissions and the user's selection. A token can never exceed the user, and
the user decides which of their permissions a client receives.

The route permission check is the existing one: each HTTP route and RPC action
keeps the permission declared in `ManagementPermissions()`, and each MCP tool
uses the permission of the operation it runs. Nothing duplicates the
route-to-permission mapping, so a new API operation is covered for OAuth the
moment it is classified.

### Audience binding (RFC 8707)

Codes, grants, access tokens and refresh tokens are bound to exactly one
canonical resource URI. A token for `ISSUER/mcp` is rejected by the management
API and the other way round, and a refresh can never change the resource. The
resource is checked at authorization, at code exchange (`resource` must match
when present), at refresh, and on every request.

### PKCE and redirect URIs

Only S256 is supported. `plain` and requests without PKCE are rejected. Redirect
URIs are registered exactly, with no wildcards, fragments or user information.
HTTPS is accepted for every client. HTTP is accepted only on loopback hosts,
where the port of a loopback IP literal may vary as RFC 8252 requires for
native apps. Private-use schemes (`com.example.app:/cb`, `cursor://…`) are
accepted only for public clients. Script-capable and local schemes
(`javascript:`, `data:`, `file:` and others) are always rejected.

### Refresh token rotation and reuse detection

Every refresh revokes the presented refresh token and issues a new pair inside
one SQLite transaction. Presenting a rotated refresh token again means the
family may be stolen: the whole grant is revoked, including the newest tokens,
and `oauth.refresh.reuse_detected` is recorded. A replayed authorization code
revokes the grant issued from it. The conditional updates that consume codes
and rotate refresh tokens guarantee single use under concurrency.

Every refresh re-evaluates the user's permissions. A refresh never restores
access the user has lost.

### Immediate revocation

There is no validation cache: each request reads the credential, grant, client
and user rows. Access stops on the next request, and open MCP or streaming
requests are cancelled within a second by the existing watchdog in
`Server.Wrap`, when any of the following happens:

| Event | Effect |
| --- | --- |
| Token revoked (RFC 7009) | Access token: that token. Refresh token: the whole grant. |
| Grant revoked by the user or an administrator | All tokens of the grant |
| User disabled | The user's grants are revoked and the credential generation changes, so re-enabling revives nothing |
| Credentials reset | All credentials including OAuth, grants revoked, generation changes |
| Role, custom role or role assignment changed | Grants whose scopes the user no longer fully holds are revoked; remaining grants are still capped by the current permissions |
| Client disabled or deleted, or its scopes or resources narrowed | Its tokens stop working; deletion removes its grants |
| Resource disabled, server disabled or issuer changed | All tokens of the affected resources stop working |

### Browser protections

The consent APIs require a session and the existing trusted-Origin check for
cookie mutations (CSRF). The consent page refuses to render inside a frame, and
the authorize endpoint sends `X-Frame-Options: DENY` (clickjacking). A pending
request can be decided once. The redirect target is always a registered URI,
never a request parameter that was not validated (open redirect).

The discovery, token, revocation and registration endpoints answer CORS
requests from any origin with `Access-Control-Allow-Origin: *` and without
credentials, because they never read cookies. `/mcp` and `/api/` keep the
trusted-Origin policy.

### Dynamic registration

Open registration is bounded to 512 dynamic clients, and dynamic clients that
never received a grant are reclaimed after 24 hours. The OAuth endpoints are
rate-limited per peer. Dynamic clients are labelled as self-registered on the
consent page. They still need a signed-in user's explicit consent and can
receive at most that user's delegable permissions.

### Audit

OAuth events use the existing security audit and its forwarding. Structured
details (client, resource, grant, credential, scopes) are stored in the event's
`changes` field under `oauth`. Tokens, codes, client secrets and PKCE verifiers
are never recorded.

`oauth.client.created`, `oauth.client.updated`, `oauth.client.disabled`,
`oauth.client.deleted`, `oauth.settings.updated`, `oauth.authorization.started`,
`oauth.authorization.failed`, `oauth.authorization.approved`,
`oauth.authorization.denied`, `oauth.code.issued`, `oauth.code.consumed`,
`oauth.token.issued`, `oauth.token.refreshed`, `oauth.token.revoked`,
`oauth.refresh.reuse_detected`, `oauth.grant.revoked`,
`oauth.authentication.failed`, `oauth.permission.denied`.

Requests made with OAuth tokens are also recorded by the existing middleware
events (for example `configuration.sensitive_change_authorized`) with auth
method `oauth`.

## Storage

Migration 17 (`management_oauth_server`) of the private management database:

- `management_oauth_server`: the single settings row.
- `management_oauth_clients`: registered clients with redirect URIs, type,
  authentication method, secret verifier, allowed scopes and resources.
- `management_oauth_grants`: grants with owner, client, resource, scopes,
  credential generation, expiry, last use and revocation reason.
- `management_oauth_codes`: authorization code verifiers with PKCE challenge,
  exact redirect URI, resource and scopes. Expired codes are deleted whenever
  a code is issued.
- `management_credentials` gains the kinds `oauth_access` and `oauth_refresh`
  and a `grant_id` column (`ON DELETE CASCADE`). The table is rebuilt only to
  widen its kind constraint; every existing row and column is copied unchanged.
  API tokens and sessions behave exactly as before, and pruning of revoked API
  tokens and sessions no longer touches OAuth rows, which are bounded per grant.

Like other identity data, none of this is part of configuration backups.

## Android and embedded mode

Native Android does not install the identity middleware. It therefore has no
Authorization Server, no `/mcp` endpoint, no OAuth tables and no
`management.db`. Anonymous loopback management and the explicit HTTPS Allow LAN
opt-in are unchanged. The shared packages compile for Android, but only server
executables enable them.

## Not implemented

- `client_credentials`: the grant table in `authorization_server_flow.go` is the
  extension point. It needs a dedicated service identity with its own
  administrator-assigned permissions, so that a machine client never borrows a
  person's account. API tokens remain the mechanism for CLI and simple
  automation.
- Client ID Metadata Documents: clients are identified by registered client IDs.
  Fetching a client's metadata URL would be a separate resolver in front of the
  client lookup.
- Token introspection (RFC 7662) and JWT access tokens: all resource servers run
  in this process and validate tokens directly against SQLite.
