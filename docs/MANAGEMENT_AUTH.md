# Local management identities

Management APIs require a local identity. This applies to every registered v2
RPC, event/log stream, profiler route, `/debug/pprof/`, and `/metrics`. Static UI
assets and the explicitly listed authentication exchanges remain public.
Proxy, VPN, inbound protocol authentication, routing and traffic identities are
unchanged. This implements the management API slice of issue #607.

## Bootstrap and migration

Run on the machine that owns the data directory:

```sh
yuhaiin auth bootstrap -path /your/data-directory -login admin
```

This creates a pending administrator and prints an enrollment capability once.
It expires after 15 minutes. There is no remote administrator bootstrap route;
the management API stays locked until enrollment completes. Starting a process
or installing an update never creates an anonymous administrator.

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

Lost/expired enrollment or lost-password recovery requires local execution:

```sh
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
Remote management therefore requires HTTPS and a trusted TLS endpoint. The
embedded CLI listener is HTTP: place a TLS reverse proxy on the same host and
bind the backend to loopback. Restrict access to that backend and configure the
frontend's exact trusted Origin when using a custom remote frontend. TLS
forwarding headers are never trusted as evidence of encryption; direct remote
plaintext management is refused even with valid credentials. Redact Authorization
and authentication request bodies in reverse-proxy logs and telemetry.

## Sessions, tokens and browser behavior

Login returns an opaque, random, revocable session secret with an eight-hour
absolute expiry. Send it as `Authorization: Session <secret>` and discard it on
logout (`DELETE /api/v2/auth/session`). Browser code keeps it in memory only;
never persist it in local/session storage, IndexedDB, service workers or URLs.
This API does not issue or accept session cookies. Authentication is explicitly
attached to requests, so there are no ambient-cookie CSRF credentials. Trusted
Origin checks still apply to every management operation and login/enrollment.
Untrusted preflights are denied; browser clients must use JSON and explicit
Authorization headers. Cross-origin clients must use `credentials: 'omit'`.

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
administrator capabilities. Available scopes are defined in
`pkg/managementauth/permissions.go`; `/api/v2/auth/me` returns effective permissions.
No wildcard scope is accepted. Each actual HTTP method/registered RPC action has
an explicit permission; unclassified handlers deny even administrators.

## Management API

| Method/path | Purpose/required scope |
| --- | --- |
| GET `/api/v2/auth/me` | Principal and effective permissions; `identity:read` |
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
