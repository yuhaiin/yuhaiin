# Proxy users and upstream credentials

This feature extends local management identities with independent traffic
credentials. It requires the server identity module; Android and core-only
embeddings retain their existing inline credentials without loading that module.

## Users and device credentials

The `none` management role grants only `identity:read` and
`proxy-credentials:own`: users can view their identity and manage their own device
credentials, with no configuration, node, API-token or status access. Existing
`admin` and `read-only` accounts also gain credential self-service. The separate
`proxy-credentials:manage` permission permits managing credentials for other
owners. Existing management API tokens retain their original scope snapshots.

Each user can have up to 64 active inbound credentials, for example one per
phone, computer or router. A generated `yp_...` secret appears once, on creation
or rotation. Each credential has a name, optional expiry, optional inbound IDs,
and optional protocols (`http`, `socks5`, `yuubinsya`, `hysteria2`, `sstp`). Empty scope
lists permit all supported protocols or inbounds that explicitly authorize the
owner. A credential never grants access to an otherwise unauthorized inbound.
Rotation atomically replaces the credential and closes its previous sessions;
revocation and account disablement/reset invalidate active sessions. Re-enabling
a user cannot resurrect old credentials. Local recovery commands in another
process propagate within one second; management mutations reload synchronously.
An expired credential cancels its sessions at its deadline without polling.
An expiry of `0` means permanent validity; the UI selects this explicitly by
default. Revocation retains the inactive record for inspection. Deletion removes
the record and immediately cancels its sessions, including for active credentials.
New issuance automatically prunes revoked, expired and reset-invalidated records
for that owner, so retained credentials do not accumulate beyond the 64-row cap.
Security events remain in their separately bounded audit history.

HTTP and SOCKS5 clients use the user's login name and generated secret. Hysteria2
uses the secret as `auth`; Yuubinsya uses it as `password`, including with existing
clients and packet formats. Usernames remain case-insensitive. User secrets do
not authenticate management APIs, and management passwords, sessions and API
tokens do not authenticate proxy traffic. SSTP uses the user's login name and
per-device secret through MS-CHAPv2. Because that protocol requires an NT hash,
a password-equivalent verifier is retained only in the private management
database for newly issued and rotated device credentials. Existing credentials
must be rotated before using SSTP, and SSTP never accepts an API login password.
Revocation and user disablement close SSTP sessions as well.

Private `management.db` stores SHA-256 verifiers of random secrets. For Yuubinsya
it stores a second SHA-256 of the protocol's wire token, not the replayable wire
token itself. Protocol authentication is a bounded in-memory lookup, with no
password KDF or database access on the packet path. These bearer secrets still
require an appropriately protected transport; the existing proxy protocols do
not gain replay protection or encryption from this feature.

Management routes, under the same HTTPS, Origin and permission checks:

- `GET /api/v2/auth/proxy-credentials?owner=USER_ID` (defaults to self)
- `POST /api/v2/auth/proxy-credentials` with
  `{"owner":"USER_ID","name":"phone","inbounds":[],"protocols":[],"expiresAt":0}`
- `DELETE /api/v2/auth/proxy-credentials/{id}`
- `POST /api/v2/auth/proxy-credentials/{id}/revoke`
- `POST /api/v2/auth/proxy-credentials/{id}/rotate`

Ordinary lists never contain secret or verifier material.

## Inbound compatibility

The optional top-level field explicitly selects traffic authentication:

```json
{
  "authentication": { "mode": "users", "users": ["USER_ID"] }
}
```

Modes are `legacy` (the original shared/anonymous protocol configuration),
`users` (only selected users' traffic credentials), and `mixed` (explicitly both).
`users` removes shared credentials from the runtime protocol configuration while
preserving the saved settings. Legacy access never acquires a user identity.
The UI defaults newly enabled user authentication to `users` and warns for mixed
mode, where disabling a user cannot revoke an independent shared password.

For migration, absent `authentication` keeps legacy behavior, including anonymous
access. An existing authentication object without `mode` keeps its previous mixed
behavior. An empty `users` list admits no user credentials. In users/mixed mode,
empty legacy authentication fields do not permit anonymous access. Selecting
users with explicit legacy mode is invalid. Users/mixed authentication without
the optional identity module fails explicitly. See
[traffic identity foundations](enterprise-identity.md) for group snapshots,
membership revocation, identity-aware routing and migration details.

Supported listeners: HTTP, SOCKS5, Mixed, Yuubinsya, Hysteria2 and SSTP. Mixed disables
SOCKS4 while user authentication is enabled because SOCKS4 has no password proof.
Authenticated SOCKS5 UDP uses a relay port associated with the authenticated TCP
control connection and pinned to its peer IP/source port; the legacy shared UDP
socket does not forward packets in this mode. Closing the TCP association stops
its relay. Clients and firewalls must permit the returned UDP relay port.

Traffic metadata carries only user ID and credential ID through TCP, UDP, ping
and connection observations. UDP mappings are isolated by credential, inbound
and source/migration ID; destinations do not split full-cone sockets. Removing or
reconfiguring a listener cancels its user sessions without revoking credentials
on another inbound. HTTP user-authenticated forwarding disables upstream
keepalive reuse to prevent connections crossing identities.

TUN, TProxy, Redir, SOCKS4, WireGuard and other listener types are outside this
change. Identity-aware routing conditions are available; dedicated traffic access authorization
and outbound access restrictions remain follow-ups.

## Shared upstream credentials

These secrets authenticate outbound connections to remote servers and have no
local user owner. A node protocol layer can use:

```json
{
  "type": "socks5",
  "credentialRef": "CREDENTIAL_ID",
  "socks5": { "user": "", "password": "", "hostname": "" }
}
```

Each layer in a chain, including TCP/UDP split children, has its own reference.
HTTP/SOCKS5 require `username-password` credentials. Yuubinsya, Hysteria2,
Shadowsocks, ShadowsocksR, Trojan and AEAD require `password` credentials. Other
protocols reject references. Obfuscation passwords, including Salamander, are
separate fields and remain inline.

A reference conflicts with nonempty inline authentication fields. Without a
reference, the existing inline behavior is unchanged. Missing references, absent
identity modules and incompatible credential types fail closed, without fallback
to inline or anonymous authentication. Runtime resolution copies the protocol;
configuration responses and exports retain only the reference. Replacement and
deletion invalidate affected cached node proxies; subsequent lookups also check
credential revisions. Existing active flows follow each protocol's ordinary
proxy-close behavior, as when updating a node.

`upstream-credentials:manage` protects all of:

- `GET /api/v2/auth/upstream-credentials` (metadata only)
- `POST /api/v2/auth/upstream-credentials` with
  `{"name":"office","type":"username-password","username":"alice","password":"secret"}`
- `PUT /api/v2/auth/upstream-credentials/{id}` (complete replacement; type immutable)
- `DELETE /api/v2/auth/upstream-credentials/{id}`

Upstream secrets must be recoverable for dialing. They are stored in the private,
owner-readable database; this feature does not claim encryption at rest. Lists
and mutation responses return only ID, name, type and revision. Neither identity
nor upstream secrets are included in ordinary configuration backup/restore.
After restoring configuration on another instance, recreate its referenced
upstream credentials explicitly; unresolved references remain unusable.
