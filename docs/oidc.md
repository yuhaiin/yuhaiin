# Generic OpenID Connect

Generic OIDC extends the existing local users, OAuth popup, account binding,
password login and recovery paths. It is optional server management code and is
not part of Android initialization or proxy forwarding. Local users and custom
roles remain the source of management permissions.

## Setup and account linking

In Account & Security, open identity provider settings and add an OpenID Connect
provider. Enter its exact HTTPS issuer, display name and client ID. The form
allocates a stable provider ID and callback before saving so the exact callback
can be registered with the IdP. Register it as an Authorization Code client with
PKCE S256. Enter a client secret for a confidential client; public clients use
PKCE without a secret. Issuers, discovery endpoints, token/JWKS endpoints and
generic callbacks require HTTPS with trusted certificates. The issuer is
immutable; replace a provider to change identity authority.

Sign in locally and explicitly link the external identity to the current account.
After linking, its provider appears on the sign-in page. Matching email addresses,
`email_verified`, IdP groups and `roles` claims never create accounts, bind existing
accounts or grant administrator privileges. A verified issuer + subject may bind
to only one local account, including legacy Google identities migrated into the
same issuer namespace. To replace such a provider binding, unlink it explicitly
before linking another configuration for the same identity.

Keep local passwords and the existing offline recovery procedure available.
IdP unavailability does not replace or block those local paths. MFA is delegated
to the IdP; SCIM, directory synchronization, refresh-token storage and back-channel
logout are not implemented. Disabling/deleting a local user, unlinking an account,
or changing/disabling/deleting the provider revokes the applicable local sessions.
Existing authenticated HTTP requests revalidate credentials on the existing
one-second interval. External IdP logout alone does not revoke an already-issued
local session; use the session management/revocation controls.

## Verification and bounds

Discovery and ID token verification use
[`coreos/go-oidc`](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc), following
[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html).
The existing OAuth flow supplies independent random state/start proofs, one-use
completion, popup/controller Origin binding and PKCE S256. OIDC additionally binds
a nonce and verifies signature, exact issuer, audience, expiry, issued-at and
not-before. Multiple audiences require `azp` to equal this client; any supplied
`azp` must match. `at_hash`, when supplied, must validate against the access token.
The ID token must be issued within the login flow's time window (one minute clock
skew). Keep server and IdP clocks synchronized. Key rotation uses the library's
cached JWKS refresh. Neither provider access tokens nor ID tokens are persisted,
returned to the UI, or used as proxy credentials.

There are at most 32 configured providers, one generic configuration per exact
issuer, 256 pending five-minute OAuth flows and eight concurrent OIDC discovery/token-validation operations.
Concurrent starts coalesce discovery for the same configuration; cached discovery
expires after 15 minutes, and the explicit status check fetches fresh discovery. Discovery/token/
JWKS HTTP responses are limited to 1 MiB, ID tokens to 64 KiB, client secrets to
2,048 bytes and subjects to 255 bytes. Provider operations use bounded timeouts;
HTTP redirects and insecure discovered endpoints are rejected. No IdP request or
identity database query is made on the forwarding path.

## Configuration, permissions and durability

Provider settings require `security:read`; writes require `security:write`.
Changing or clearing a client secret also requires `secrets:manage`. Provider configuration inspection and
writes remain session-authenticated, preserving the existing OAuth boundary. Client secrets are write-only, omitted from
settings/public discovery/audits; an empty update preserves the stored value.
Clearing a configured secret is an explicit public-client option. Permission
changes never expand existing scoped tokens.

Generic provider saves check their revision inside the private SQLite transaction
and reject stale drafts. Safe before/after metadata and session revocation commit
in that transaction with the configuration. A durable audit failure rolls back
all of them. Completion also checks the current provider revision in the same
transaction as account linking or session issuance, so pending callbacks cannot
use retired configuration. HTTP provider changes invalidate pending flows and
cached discovery. Delete removes that provider's bindings and revokes its sessions.

Migration 12 upgrades only the private management database, retaining GitHub and
Google configuration, account links and existing local users. Interrupted migration
rolls back and can be retried. Management identities/OIDC client secrets remain
outside the ordinary configuration database and its backups.

`GET /api/v2/auth/oauth/providers` keeps its array-of-IDs format;
`?details=1` adds display names for public sign-in choices. Existing OAuth routes
also accept `oidc-<uuid>` provider IDs. `POST /api/v2/auth/oidc/settings` creates a
provider (a preallocated valid ID may be supplied); a controller HTTPS Origin can
be supplied to have the server construct its callback. Configuration and discovery
status share the existing `/oauth/settings` workspace. Status reports discovery
availability, not successful client authentication or availability of every IdP
service. Client credentials are exercised during an actual login.
