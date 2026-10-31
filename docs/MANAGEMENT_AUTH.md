# Local management identities

The server executable opts into `managementauth.Middleware` through
`app.StartOptions.HTTPMiddleware`. In that mode, management APIs require a local
identity. This applies to every registered v2
RPC, event/log stream, profiler route, `/debug/pprof/`, and `/metrics`. Static UI
assets and the explicitly listed authentication exchanges remain public.
Proxy, VPN, inbound protocol authentication, routing and traffic identities are
unchanged. This implements the management API slice of issue #607.

## Optional HTTP middleware and Android

The middleware is initialized after all routes are registered and wraps the
whole HTTP handler, including profiler, metrics and streams. Its database closer
belongs to the app lifecycle, and initialization failure aborts startup. Core
`app` and `httpapi` packages do not import `managementauth`; RPC permission
annotations are plain strings, validated against the module's scope registry.

`cmd/android` deliberately omits the middleware and does not import the identity
module. It creates no `management.db`, setup code or account routes. Without the
middleware, the core permits management only from actual loopback peers and
trusted browser origins. Binding an Android listener to a LAN address does not
enable anonymous remote management. Static UI files remain public.

`GET /api/v2/management` explicitly reports `{"authentication":"local-users"}`
with the module installed, or `{"authentication":"none"}` in local-only mode.
The paired Web UI uses this response to enter local mode directly, with no login,
account controls, credentials or identity polling. It only accepts `none` for a
loopback controller URL. Missing or unknown metadata never disables login.

## First-time setup and migration

Start yuhaiin normally. Until initialization completes, startup output prints a
random **Initialization code** valid for 15 minutes. Open the paired Web UI,
choose the controller URL, and use **Create administrator** to enter that code
and choose a login name and password. No extra command is needed.

If the process restarts before setup completes, it prints a fresh code and
immediately invalidates the previous one. Opening the page, requesting KDF
parameters or submitting an invalid password does not complete setup. Successful
administrator creation stores the verifier and permanently closes initialization
in one database transaction. Future starts print no code, even during password
recovery or when accounts are disabled. An expired code requires a controller
restart. The completion marker lives in the private management database.

The code is printed only to local startup output (stderr/service logs), never
returned by HTTP or included in the persistent management log stream or audit
events. Only a SHA-256 verifier is stored. HTTP setup still requires the code,
the trusted-Origin policy and TLS for remote peers; it is not first-visitor
administrator registration. Protect access to startup output until setup closes.

Manual local bootstrap remains available as an optional alternative:

```sh
# Stop the server using this data directory before the local command.
yuhaiin auth bootstrap -path /your/data-directory -login admin
```

This creates a pending administrator and prints an enrollment capability once,
valid for 15 minutes. Complete it with **Activate account** or the reference
client below. A pending account alone does not complete initialization. Normal
startup creates no anonymous account and management APIs stay locked until a
password is enrolled. An existing enrolled installation upgrades with setup
closed; migration conservatively recognizes previous enrollment/recovery history.

Using Node 22+ and the reference client in this repository:

```sh
node example/management-auth/cli.mjs enroll https://management.example
node example/management-auth/cli.mjs login https://management.example admin
```

Enrollment prompts for the capability and password without echo. The password
is transformed in the client. Login prints a revocable eight-hour session once;
handle this output as a secret. For local development, actual loopback HTTP
connections are also supported. Neither passwords nor capabilities belong in
command-line arguments, shell history, browser navigation or logging pipelines.

Existing `-u`/`-p` configuration produces a migration warning and no longer grants
management access; it does not prevent the data plane from starting. Remove
these flags after enrollment. Existing SHA-256 Basic verifiers cannot be
converted into the new client/server KDF representation. Intentionally enroll a
password through the new contract, even when reusing the previous login name.
Basic headers and the old `?token=` credential transport are rejected. There is
no automatic conversion and no unauthenticated migration HTTP endpoint.

The exported Go `app.Auth`/`HandleFunc` compatibility API remains available to
embedded callers. It is separate from account login and creates no database.
`NewAuth` now generates a random 16-byte salt and a 32-byte PBKDF2-HMAC-SHA256
verifier with 600,000 iterations. Always construct it with `NewAuth`: the public
digest fields alone, including historical unsalted SHA-256 values, cannot
reconstruct an authorized verifier. The object is process-local, not a persisted
credential format. Existing correctly authenticated Basic requests and CORS
preflights keep their behavior. There are at most two concurrent verifications
per object; canceled HTTP requests stop waiting for admission. An already
running derivation finishes before observing cancellation, without an additional
worker goroutine. The standalone server still rejects Basic login.

On a Ryzen 5 5600G, `BenchmarkLegacyBasicAuth` measured 188.6–188.8 ns per
verification before versus 88.1–88.3 ms after, and 0 versus 796 allocated bytes
(0 versus 11 allocations, two runs each). This intentionally increases the cost
of password guessing. It affects the optional embedded Basic API, not forwarding
or account-session verification. Reproduce with `go test ./pkg/app -run '^$'
-bench '^BenchmarkLegacyBasicAuth$' -benchmem -benchtime=1s -count=2`; retained
results are in [the benchmark fixture directory](benchmarks/data/legacy-basic-auth-2026-10-30/).

Lost/expired enrollment or lost-password recovery requires local execution:

```sh
# Stop the server first; restart it after local credential recovery.
yuhaiin auth recover -path /your/data-directory -id USER_UUID
```

Recovery rotates the client salt and invalidates the old password, sessions,
tokens and enrollment capability immediately, then prints a new 15-minute
capability. Accounts can also be reset by an administrator through the API.
Password changes use this same enrollment exchange after an authenticated
`POST /api/v2/auth/password/enrollment`. Complete it before the capability expires;
the old credentials stop working as soon as the reset begins.

## Exact password contract

The account stores immutable algorithm identifiers and a random 16-byte client
salt. Salt and KDF metadata can be obtained without submitting a password:

```text
POST /api/v2/auth/parameters
{"login":"admin"}

{"algorithm":"pbkdf2-sha256-v1","salt":"BASE64URL_NO_PADDING",
 "iterations":600000,"digest":"SHA-256","bytes":32,
 "normalization":"NFC","encoding":"utf-8/base64url-unpadded"}
```

Known, unknown, disabled and pending accounts have the same response shape and
parameter sizes. Unknown accounts receive a stable server-keyed pseudorandom
salt; login failures return the same generic 401 and perform the server KDF.
Login names are case-insensitive ASCII letters/digits plus `.`, `-`, `_`, 1–64
characters. Their casing does not affect the salt.

The browser rejects unpaired UTF-16 surrogates, normalizes the password to Unicode
NFC, encodes UTF-8 without trimming, and runs PBKDF2-HMAC-SHA-256 with 600,000
iterations and the decoded 16-byte client salt. Passwords must contain 1–1024
UTF-8 bytes after normalization. The result is 32 bytes, encoded as canonical
unpadded base64url (43 ASCII characters). `example/management-auth/client.mjs`
uses standard Web Crypto and is the executable browser/Node reference.

```text
POST /api/v2/auth/login
{"login":"admin","clientCredential":"BASE64URL_32_BYTES"}
```

For enrollment, request `POST /api/v2/auth/enrollment/parameters` with
`Authorization: Enrollment <capability>` to retrieve the account parameters;
submit `{"clientCredential":"..."}` to `POST /api/v2/auth/enrollment` with the
same header. The capability is consumed atomically. Initial bootstrap, creating
another account, password change and administrator recovery all use this flow.
Raw `password` fields are rejected; backend APIs never receive a raw password.

The backend decodes the client credential and applies Argon2id v0x13 with an
independent random 16-byte server salt, 65,536 KiB memory, three iterations, one
lane and a 32-byte output. Only that verifier and the two salts are persisted.
Comparison is constant-time, and at most two Argon2id computations run at once.
The immutable database ID `argon2id-v1` identifies these parameters; future
parameter changes need a new ID and explicit credential reenrollment. The
[OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
describes the underlying KDF choices.

**The client credential is reusable and password-equivalent. Capturing it permits
replay/pass-the-hash. Client-side hashing does not provide replay protection.**
Remote management therefore requires HTTPS. By default the CLI serves HTTP and
HTTPS on the same TCP port and identifies the protocol from the first bytes of
each connection. The default port is `50051`; only that port needs to be exposed.
Remote HTTP page requests redirect to HTTPS on the same port, while remote
plaintext API requests remain refused. Local HTTP clients continue to work.
If no certificate is configured, yuhaiin creates a self-signed certificate and
stores it with owner-only permissions at `management-tls.pem` in the data
directory. The certificate persists across restarts, and startup prints its
SHA-256 fingerprint and candidate HTTPS URLs. Browsers may show a certificate
warning; compare the fingerprint through a trusted channel before continuing.
Accepting an untrusted certificate does not authenticate the server against an
active man-in-the-middle. Use a certificate trusted by your clients for public
or shared deployments. This server certificate is separate from the HTTP
Gateway CA, which signs certificates for explicitly enabled TLS interception.

Set `-https-names` on first startup to include additional DNS names or IP
addresses in the generated certificate. If the certificate already exists,
remove `management-tls.pem` from the data directory before restarting to apply
new names. To use an existing certificate, set both `-https-cert` and
`-https-key`. Use `-https=false` to disable HTTPS when TLS is terminated by a
local reverse proxy. The listener uses the address from `-host`, so a loopback
bind remains loopback-only. When using a custom remote frontend, configure its
exact trusted Origin. TLS forwarding headers are never trusted as evidence of
encryption; direct remote plaintext management is refused even with valid
credentials. Redact Authorization and authentication request bodies in proxy
logs and telemetry.

For the default port, allow TCP `50051` through the server firewall. If `-host`
uses another port, expose that one port for both HTTP and HTTPS.

## Local reverse proxies and Cloudflare Tunnel

For a Tunnel service such as `http://127.0.0.1:50051`, keep the public hostname
in the forwarded `Host` header. The application accepts same-origin HTTPS
requests automatically using `X-Forwarded-Proto: https` from the loopback proxy.
No Origin allowlist entry is needed when frontend and backend share that domain.
Direct navigation and same-origin GET discovery also work without an Origin
header. Login, refresh and logout consistently use the public HTTPS cookie.

The forwarded scheme is accepted only from an actual loopback socket peer,
with one unambiguous header value. Remote clients cannot bypass the HTTPS
requirement with forwarded headers. Native local-only management still does not
provide remote anonymous access. Separate frontend origins keep their existing
trusted-Origin configuration. Proxy headers do not change recorded peer IPs.

## Passkey sign-in (WebAuthn)

Passkeys are an optional additional sign-in method for already-enrolled users.
Sign in by password or OAuth, then choose **Add Passkey** under Account & security.
Each user may have up to 20 named Passkeys. Registration requires a live browser
session, user verification and a discoverable credential. The login screen offers
a username-free Passkey button. Successful authentication issues the same
eight-hour, revocable HttpOnly session cookie as password and OAuth.

The RP ID is the hostname of the *Web UI origin*, not the controller API host.
Only exact trusted browser origins are accepted. Stable HTTPS DNS hostnames and
`http://localhost` (any port) are supported. IP literal origins such as
`127.0.0.1`, remote plaintext HTTP, and non-DNS hosts are not eligible.
Use `http://localhost:50051` instead of `http://127.0.0.1:50051` for local
Passkeys. A separately deployed UI must be configured as a trusted controller
Origin. Because credentials are scoped by RP ID, using the UI at
`https://vpn.example.com` and `http://localhost` generally requires registering
a separate Passkey at each. Ports do not affect the RP ID, but protocol and
port remain bound to the ceremony Origin.

Challenges are stored only in bounded, short-lived (five-minute), single-use
server memory. Registration binds to the original authenticated session.
Completion checks the current user, generation and session; login revalidates
credential existence and current account status transactionally. Password reset
and local recovery remove all registered Passkeys. Deletion of a Passkey does
not invalidate unrelated sessions, but new logins with that credential fail.

## Sessions, tokens and browser behavior

Login returns an opaque, random, revocable session secret with an eight-hour
absolute expiry. Header clients send `Authorization: Session <secret>`. Browser
login also sets a host-only HttpOnly cookie: HTTPS uses `__Host-yuhaiin-session`,
`Secure`, `Path=/` and `SameSite=None`; loopback HTTP uses `yuhaiin-session` and
`SameSite=Lax`. The frontend uses `credentials: 'include'` for management
requests. Secrets remain absent from URLs, browser storage and cache keys.

Before rendering routes after a refresh, `GET /api/v2/auth/session` validates the
cookie and returns only the principal and original expiry. It does not issue a
new session or extend its lifetime. Logout revokes the verifier and expires the
cookie. Browser cookie mutations validate the Origin on POST/PUT/DELETE requests.
Same-origin HTTPS requests are accepted automatically, including loopback TLS
and local reverse proxies; they need no trusted-Origin setting. Explicit Authorization takes precedence and never falls
back to a cookie on failure. Originless CLI header authentication still works.
Untrusted origins/preflights are rejected; CORS credentials are enabled only for
an exact trusted origin. Browsers that block third-party cookies may require
hosting the UI on the controller origin or allowing its cookies for the trusted
UI site. No JavaScript-readable persistent token fallback is used.

`GET /api/v2/auth/sessions` lists only the caller's active, unexpired sessions in
the current credential generation, with device User-Agent, actual socket peer IP,
login method, creation/expiry, activity time and current-session marker. The
activity timestamp is coalesced to one update per minute. Forwarded IP headers
are not trusted. `DELETE /api/v2/auth/sessions/{id}` revokes an owned session,
including the current one, without granting access to another user's sessions
or API tokens. Both endpoints require session authentication. Revocation blocks
the next request and cancels existing streams through the usual one-second gate.

API tokens use `Authorization: Bearer <token>`. Full secrets are returned only at
creation/rotation; copy the result immediately into the intended secret store.
Lists expose only ID, prefix, owner, scopes, timestamps, expiry and revocation
state. Database verification uses SHA-256 of a 256-bit random secret, not the
secret itself. Tokens cannot authenticate as sessions or enrollment capabilities.

Every request checks current owner status, credential generation, token expiry
and scopes from SQLite. Permissions are the intersection of the owner's current
role and the token's fixed scopes. Empty scopes at creation snapshot the current
role, so later role promotion cannot broaden a token. A scoped token cannot
create a broader token. Disabling then re-enabling a user cannot revive previous
tokens or sessions. Active streams recheck authorization every second and cancel
their request context on revocation or permission loss.

Roles are `admin` and `read-only`. Read-only permits configuration and status
reads but no mutation, network-active diagnostics, logs, memory profiling, backup,
update installation or user administration. Configuration reads can include
upstream credentials, so read-only users are trusted operators. Sensitive scopes
such as `users:manage` permit credential administration and must be treated as
administrator capabilities. The complete permission catalog is available at
`GET /api/v2/auth/permissions` to authenticated users with `identity:read`; each
entry includes its stable string ID, category, and description. The typed
identifiers are defined in `pkg/management/permission`.
`/api/v2/auth/me` returns the current principal's effective permissions. No
wildcard scope is accepted. Each actual HTTP method/registered RPC action has
an explicit permission; unclassified handlers deny even administrators.

## Management API

| Method/path | Purpose/required scope |
| --- | --- |
| GET `/api/v2/auth/me` | Principal and effective permissions; `identity:read` |
| GET `/api/v2/auth/permissions` | Permission catalog; `identity:read` |
| GET `/api/v2/auth/setup` | Public initialization state and expiry, never the code |
| POST `/api/v2/auth/setup/parameters` | Client KDF parameters; `Authorization: Setup <code>` |
| POST `/api/v2/auth/setup` | Atomic administrator creation; same Setup header, `{login,clientCredential}` |
| GET/POST `/api/v2/auth/users` | List/create accounts; `users:manage` |
| GET/PUT/DELETE `/api/v2/auth/users/{id}` | View/update/delete; `users:manage` |
| POST `/api/v2/auth/users/{id}/enrollment` | Reset credentials; `users:manage` |
| POST `/api/v2/auth/password/enrollment` | Own password change; session authentication |
| DELETE `/api/v2/auth/session` | Revoke current session |
| GET/POST `/api/v2/auth/tokens` | List/create own tokens; `tokens:own` |
| DELETE `/api/v2/auth/tokens/{id}` | Revoke; own token or `tokens:manage` |
| POST `/api/v2/auth/tokens/{id}/rotate` | Atomic rotation; preserves scopes and expiry |
| GET `/api/v2/auth/events` | Latest 1,000 redacted security events; `security:read` |

Create users with `{"login":"reader","role":"read-only"}`. The result contains
the user and a one-time enrollment capability. PUT accepts `login`, `role`, and
`disabled`. SQLite triggers prevent deleting, disabling or demoting the last
active enrolled administrator; a pending administrator does not satisfy this
guard. Create tokens with `{"scopes":["nodes:read"],"expiresAt":UNIX_SECONDS}`;
omit/zero expiry for no expiry. Optional `owner` selects another user and requires
`tokens:manage`; listing another user's tokens uses `?owner=USER_UUID`.

Authentication failures return 401, permission failures 403, and protected
responses use `Cache-Control: no-store`. Auth errors expose no SQL or submitted
credentials. Login/enrollment/parameter requests share per-process limits of 20
requests per source IP per minute and 120 globally per minute; at most 1,024 IP
windows are retained. Client IP comes from the actual connection, so reverse
proxy deployments should also rate-limit at the TLS edge. Up to 1,024 accounts
and 64 live credentials per account keep management state bounded. Expired and
revoked credential records are pruned on issuance; security events retain no
passwords, derived credentials, token secrets, request bodies or URLs.

Identities live in a private `management.db` next to `state.db`, using the same
SQLite migration and file/journal protection machinery. Configuration export,
S3 state snapshots and restoration of `state.db` cannot disclose or replace local
identities. Treat deliberate filesystem backups of `management.db` as sensitive.

The paired frontend is implemented in
[yuhaiin-react PR #521](https://github.com/yuhaiin/yuhaiin-react/pull/521): account
activation/login, user and token management, permission-aware controls, and
authenticated streams/profiler content. Ship the frontend and backend together;
the previous Basic/query-token frontend cannot manage this backend. UI
visibility never replaces backend enforcement. The executable client reference
remains available under `example/management-auth`.

Inbound user credentials and shared outbound secrets are documented in [Proxy credentials](proxy-credentials.md).

## GitHub and Google OAuth

Administrators configure OAuth applications in **Account & security → OAuth
application settings**. Create a GitHub OAuth App or a Google OAuth web client,
then save its client ID, client secret and exact callback URL:

- GitHub: `https://YOUR_CONTROLLER/api/v2/auth/oauth/github/callback`
- Google: `https://YOUR_CONTROLLER/api/v2/auth/oauth/google/callback`

Google supports this flow. Configure its consent screen/audience and add test
users while the app is in testing. Production remote callbacks require public
HTTPS and a reachable controller. HTTP callback URLs are restricted to loopback.
The browser must allow the sign-in popup. With a separate UI origin, allow it in
the controller's existing trusted-Origin settings. Callbacks return to the
controller; the popup posts a one-use completion proof to the initiating UI.

Provider settings and bindings live only in private `management.db`, outside
configuration exports/restores. Settings responses never return client secrets;
a blank secret on update keeps the existing one. Disabling a provider removes
its app configuration and pending flows while retaining account bindings.

Users first enroll a local account and connect GitHub/Google from **Connected
accounts**. Sign-in accepts only already-linked, enabled, enrolled local users
with their current local role. There is no public signup, email matching or
implicit linking. Identity keys are GitHub numeric `id` and Google `sub`, never
mutable usernames or email addresses. Disconnecting revokes that provider's
sessions; password credential resets clear all bindings along with sessions and
tokens. Password sign-in remains available after disconnecting a provider.

OAuth uses authorization code + S256 PKCE. Five-minute pending grants are bounded
to 256, rate-limited, single-use and lost on restart. Starts and completions require
a trusted browser Origin. The callback page uses a nonce CSP and posts only to
the captured UI origin. Completion also requires the secret from the initiating
POST; session/provider tokens never appear in callback URLs or window messages.
Link completion revalidates the exact initiating session in its database
transaction. Provider access tokens are used only for the provider's authenticated
userinfo API, then discarded. Neither access nor refresh tokens are stored.

| Endpoint | Purpose |
| --- | --- |
| GET `/api/v2/auth/oauth/providers` | Public list of enabled provider names |
| GET `/api/v2/auth/oauth/settings` | Admin session: app settings without secrets |
| PUT/DELETE `/api/v2/auth/oauth/settings/{provider}` | Admin session: configure/disable |
| POST `/api/v2/auth/oauth/{provider}/start` | Public login start; trusted Origin |
| POST `/api/v2/auth/oauth/{provider}/link` | Own session: binding start |
| GET `/api/v2/auth/oauth/{provider}/callback` | Provider redirect; state/PKCE check |
| POST `/api/v2/auth/oauth/{provider}/complete` | One-use proof exchange; exact session for links |
| GET `/api/v2/auth/oauth/links` | Own session: list connected identities |
| DELETE `/api/v2/auth/oauth/links/{provider}` | Own session: disconnect and revoke provider sessions |

Provider contracts: [GitHub web authorization](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
and [Google OpenID Connect/userinfo](https://developers.google.com/identity/openid-connect/openid-connect).
