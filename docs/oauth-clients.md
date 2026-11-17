# Using Yuhaiin OAuth from an application

This guide is for developers of applications that call the Yuhaiin management
API or its MCP server on behalf of a Yuhaiin user. The model is described in
[OAuth 2.1 Authorization Server](oauth.md).

For your own scripts and CLI use, an [API token](MANAGEMENT_AUTH.md#sessions-tokens-and-browser-behavior)
is simpler and keeps working. OAuth is for third-party applications that should
receive only the access a user approves, for a limited time, and that the user
can revoke.

Throughout, `ISSUER` is the issuer configured by the administrator, for example
`https://yuhaiin.example.com`.

## 1. Discover the endpoints

```sh
curl -s ISSUER/.well-known/oauth-authorization-server
```

```json
{
  "issuer": "https://yuhaiin.example.com",
  "authorization_endpoint": "https://yuhaiin.example.com/oauth/authorize",
  "token_endpoint": "https://yuhaiin.example.com/oauth/token",
  "revocation_endpoint": "https://yuhaiin.example.com/oauth/revoke",
  "registration_endpoint": "https://yuhaiin.example.com/oauth/register",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
  "authorization_response_iss_parameter_supported": true,
  "scopes_supported": ["configuration:read", "nodes:read", "nodes:write", "..."]
}
```

Each protected resource publishes RFC 9728 metadata:

```sh
curl -s ISSUER/.well-known/oauth-protected-resource/api
curl -s ISSUER/.well-known/oauth-protected-resource/mcp
```

An unauthenticated request to a resource answers `401` with
`WWW-Authenticate: Bearer resource_metadata="ISSUER/.well-known/oauth-protected-resource/<id>"`.

## 2. Register a client

Either ask an administrator to create the client under **Account & security →
OAuth applications**, which shows a confidential client's secret once, or
register dynamically (RFC 7591) when the administrator allows it:

```sh
curl -s -X POST ISSUER/oauth/register -H 'Content-Type: application/json' -d '{
  "client_name": "My dashboard",
  "redirect_uris": ["http://127.0.0.1/callback"],
  "token_endpoint_auth_method": "none"
}'
```

- Public clients (`none`) are native or browser apps without a secret.
- Confidential clients use `client_secret_basic` or `client_secret_post` and
  receive `client_secret` once.
- Redirect URIs must match exactly. Use HTTPS, an `http://` loopback address
  (where any port is accepted for loopback IPs), or a private-use scheme for
  public native apps. Wildcards are not supported.
- `scope` limits the scopes the client may ever request. When omitted, the
  client may request any delegable scope.

## 3. Choose the resource and scopes

| Resource | Indicator (`resource`) | Typical scopes |
| --- | --- | --- |
| Management API | `ISSUER/api` | `nodes:read`, `connections:read`, `settings:read`, … |
| MCP server | `ISSUER/mcp` | `mcp:connect` plus tool permissions |

Scopes are Yuhaiin permission IDs. `GET /api/v2/auth/permissions` lists them
with descriptions, and `delegable: true` marks the ones a client may request.
Request the fewest you need. A token is always limited to what the approving
user can do at the moment it is used.

A token works only at the resource it was issued for. To use both the API and
MCP, obtain a token for each.

## 4. Authorization code flow with PKCE

Create a verifier and an S256 challenge:

```sh
verifier=$(openssl rand -base64 48 | tr -d '=+/' | cut -c1-64)
challenge=$(printf %s "$verifier" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')
```

Send the user's browser to:

```text
ISSUER/oauth/authorize?response_type=code
  &client_id=CLIENT_ID
  &redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback
  &scope=nodes%3Aread%20connections%3Aread
  &resource=https%3A%2F%2Fyuhaiin.example.com%2Fapi
  &state=RANDOM_STATE
  &code_challenge=CHALLENGE
  &code_challenge_method=S256
```

The user signs in to Yuhaiin if necessary and approves or denies. Yuhaiin then
redirects to `redirect_uri` with `code`, your `state` and `iss`. Check that
`state` is the one you sent and that `iss` equals the issuer.

Exchange the code within five minutes:

```sh
curl -s ISSUER/oauth/token \
  -d grant_type=authorization_code -d code=CODE \
  -d redirect_uri=http://127.0.0.1:8765/callback \
  -d code_verifier="$verifier" -d client_id=CLIENT_ID \
  -d resource=ISSUER/api
```

```json
{"access_token":"yuat_…","token_type":"Bearer","expires_in":900,"refresh_token":"yurt_…","scope":"nodes:read connections:read"}
```

The response `scope` is what was actually granted, which can be fewer scopes
than you requested. Confidential clients authenticate with HTTP Basic
(`-u CLIENT_ID:SECRET`) or `client_secret` in the body, whichever they
registered, and omit `client_id`. Parameters must be sent in the form body,
never in the query string.

## 5. Call the management API

The management API is the existing v2 HTTP API. OAuth access tokens are
accepted alongside sessions and API tokens, with the same permission per route:

```sh
curl -s -X POST ISSUER/api/v2/rpc/nodes.get \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' -d '{"page":1,"page_size":50}'

curl -s -X POST ISSUER/api/v2/rpc/connections.total \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' -d '{}'
```

Responses redact secrets as for any caller without the explicit
`X-Yuhaiin-Secret-Access: reveal` capability, which OAuth clients cannot obtain.

| Status | Meaning |
| --- | --- |
| `401` + `error="invalid_token"` | Expired, revoked, issued for another resource, or the grant, client or user is no longer active. Refresh, or start over if refreshing fails. |
| `403` + `error="insufficient_scope", scope="…"` | The token lacks the route's permission. Request that scope in a new authorization. |

## 6. Refresh

```sh
curl -s ISSUER/oauth/token -d grant_type=refresh_token \
  -d refresh_token="$REFRESH_TOKEN" -d client_id=CLIENT_ID
```

Each response contains a new refresh token. Store it and discard the previous
one: a refresh token is accepted once. Sending an already-used refresh token
revokes the whole authorization, so never refresh concurrently with the same
token. You may narrow `scope`, but you cannot add scopes or change `resource`.

## 7. Revoke

```sh
curl -s ISSUER/oauth/revoke -d token="$REFRESH_TOKEN" -d client_id=CLIENT_ID
```

Revoking a refresh token ends the authorization and all of its access tokens.
Revoking an access token ends only that token. The endpoint answers `200` for
unknown tokens, as RFC 7009 requires. Users can also revoke an application
under **Account & security → Authorized applications**.

## Browser-based clients

The discovery, token, revocation and registration endpoints allow CORS from any
origin without credentials. The management API and `/mcp` accept cross-origin
browser requests only from origins the administrator trusts, so browser-based
clients on other origins should call them from a backend.
