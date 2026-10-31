# Traffic identity foundations

This is the first backend increment of the enterprise identity work. It adds
traffic groups, identity conditions in the existing router, explicit inbound
authentication modes and historical group IDs in connection audits. It does not
by itself provide traffic authorization. The follow-up
[Traffic Access Policy](traffic-access.md) adds the dedicated gate. User resource
policies extend the same engine in [Resource governance](resource-governance.md).
Enterprise security management is a subsequent phase. Routing conditions alone
must not be used as an enterprise authorization boundary.

## Ownership and migration

Core networking still depends only on `pkg/net/proxyauth` identity capabilities.
It does not import the optional management authentication implementation.
Native Android does not open an identity database. The SQLite management store
migrates from schema 7 to schema 8 atomically, adding `traffic_groups` and
`traffic_group_members`, indexes and membership integrity triggers. Existing
users, credential verifiers, roles, sessions and configuration are preserved.
The configuration database is unchanged; audit JSON accepts the optional
`groupIds` field, while existing audit records remain readable without it.

Groups have immutable generated UUIDs, a name, optional description, members
and a revision. They do not grant management permissions. `users:manage` is
required for every group API; ordinary users cannot add themselves to groups.
A save replaces metadata and memberships in one transaction together with its
management security event. A stale revision fails with 409. Invalid users,
duplicate members and conflicting names leave the previous group untouched.

Limits are 1,024 active groups, 1,024 members per group, 64 groups per user and
4,096 group records including deleted groups. Deletion atomically removes all
memberships and retains an immutable tombstone, inspectable by ID. This preserves
existing references and prevents a new group with the same name inheriting an
old group's identity. Ordinary edits cannot reactivate tombstones or assign new members.
The [configuration-change workflow](configuration-changes.md) can explicitly
restore a deleted group under its original ID after current permission, name,
user and membership-limit checks. They count toward the explicit retained-record cap. Group names may be
reused with a new ID. Deleting a user removes its memberships and advances the
revisions of affected groups. Management and connection audits retain stable IDs.

Authentication reload reads all memberships and credentials in one consistent
read transaction. Membership slices are sorted and shared by all credentials of
an owner, and unchanged slices are reused across reloads. Authentication and
routing use memory, not SQL. Group writes synchronously reload the authentication
snapshot before a successful HTTP response; other-process changes are observed
within one second. Changed membership cancels only the affected owners' traffic
identities, including their active credential/listener scopes. Existing TCP and
UDP revocation machinery closes those sessions. Management sessions and roles
are independent. Unchanged memberships retain their existing identity contexts.
A credential/membership database read failure invalidates the traffic
authentication snapshot. If resource-policy preparation fails after metadata
loads successfully, changed identities remain invalid while unchanged identities
continue authenticating. Heavy resource compilation runs outside the authentication
read lock, and new metadata publishes only after its resource bindings activate.
A failed response after a successful persistence commit can therefore require
reloading the current revision before retrying.

## APIs

All endpoints follow the existing `/api/v2/auth` HTTPS, Origin, authentication,
permission and safe error handling conventions:

- `GET /groups`: active groups and their members.
- `GET /groups/{id}`: inspect an active group or a deleted tombstone.
- `POST /groups`: `{name,description,members,revision:0}`.
- `PUT /groups/{id}`: replace with `{name,description,members,revision}`.
- `DELETE /groups/{id}?revision=N`: retire the current revision.

## Routing conditions

The existing rule compiler, AND/OR/NOT behavior, ordering and lightweight match
trace are reused. New leaves are `user`, `group` and `credential`, each with
`{ids:[...]}`. IDs within one leaf are ORed. A positive identity leaf requires a
valid authenticated traffic identity containing both user and credential IDs.
A group match succeeds when any authenticated membership intersects the compiled
set. Membership iteration is sorted and results are deterministic for overlapping
groups. HTTP headers, IP addresses, client labels and management sessions cannot
supply traffic identity.

```json
{"type":"all","all":[
  {"type":"group","group":{"ids":["GROUP_UUID"]}},
  {"type":"network","network":{"network":"tcp"}},
  {"type":"port","port":{"ports":"443"}}
]}
```

The existing Boolean semantics remain explicit: NOT over a positive identity
miss can match anonymous traffic. Route actions select forwarding behavior;
authorization is enforced separately by the [traffic access policy](traffic-access.md),
including its explicit default action. Group tombstones
have no memberships, so their positive identity conditions never match. Rule
traces expose identity condition kinds, evaluated stable IDs and results without
proofs or secret material. Connection audits snapshot group IDs at observation;
later renaming, membership updates and deletion do not rewrite history. Connection
auditing retains its existing bounded, potentially lossy buffering guarantees.

## Inbound authentication modes

`authentication.mode` accepts:

- `legacy`: shared protocol credentials and their original anonymous semantics;
  selecting users with this mode is invalid. No management identity module is
  needed for this mode.
- `users`: only the explicitly selected users' independent traffic credentials.
  The protocol server receives no shared credential in its runtime copy.
- `mixed`: explicitly accept both user credentials and configured shared
  credentials. Shared access remains unattributed and independent of user
  revocation. The UI shows this warning.

For migration, absent `authentication` remains legacy; an existing authentication
object without `mode` remains mixed. Enabling user authentication in the updated
UI starts with `users` and an empty allowlist. An empty user list admits nobody
through user credentials. Existing deployments are not silently reclassified.
The saved legacy fields are preserved so a deliberate switch back can restore
that configuration. The listeners supporting user authentication remain HTTP,
SOCKS5, Mixed, Yuubinsya and Hysteria2. Mixed disables SOCKS4 when user credential
authentication is active. Other listener types reject the authentication object.
Management credentials and proxy credentials remain separate domains.

## Qualification

See [identity benchmarks](benchmarks/identity.md). Tests cover atomic membership
replacement, privilege rejection, overlapping groups, targeted revocation,
deleted identities, optimistic revisions, tombstones, audit persistence,
interrupted migrations and restart preservation. HTTP CONNECT integration tests
exercise all authentication modes and verify that legacy traffic is not assigned
a user. Identity condition tests cover nested expressions, invalid/missing and
revoked identities and trace compilation. Run the pinned lint workflow and the
focused race suites before changing these boundaries.
