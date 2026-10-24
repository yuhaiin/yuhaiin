# Custom management roles

Management roles govern `/api/v2` capabilities; traffic groups govern network
access. Assigning a management role never changes traffic group membership.

The protected `admin`, `read-only` and `none` base roles retain their meanings.
Migration 9 adds custom role definitions and many-to-many assignments alongside
the existing user role column. The existing last-active-administrator database
triggers remain in place. Upgrades neither rewrite credentials nor replace local
administrators. A custom role containing administrator-like permissions does
not count as a replacement for the protected local administrator.

Custom roles have immutable IDs, unique names, descriptions, permission lists and
optimistic revisions. Up to 128 definitions and 32 assignments per account are
supported. A role referenced by an account cannot be deleted. Built-in roles
cannot be edited or deleted through the custom-role APIs. Permission IDs come
from the existing catalog, and unknown IDs are rejected.

Effective permissions are the union of the base role and assigned custom roles.
For a narrowly scoped role, choose `none` (Proxy-only) as the base role and add
the required permissions. For example:

| Role | Example permissions |
| --- | --- |
| Security Auditor | `security:read`, `roles:read`, `traffic-access:read`, `resources:read`, `usage:read` |
| Network Operator | Selected node, inbound, route and resolver read/write capabilities |
| Helpdesk | `users:manage` plus permissions required for accounts it may manage |
| Read-only Viewer | Protected `read-only` base role |
| Proxy-only User | Protected `none` base role |

The Proxy-only base role still grants independent own identity, proxy credential
and usage capabilities. An unenrolled or disabled account has no effective
authenticated management permissions even if its configured assignments remain.

`roles:read` inspects definitions; `roles:write` edits definitions. Assignment
also requires `users:manage`. A delegated role manager can grant only permissions
it currently holds and cannot edit or remove a stronger role/account. Built-in
role assignment, user deletion and enrollment resets enforce the same account
boundary, closing the path from a narrow helpdesk role to an administrator reset.
Sensitive grants recheck the actor inside the write transaction, bounded by the
request's original permissions. Persisting a role or assignment without its
management change audit fails the whole transaction.

Management authentication reads credentials, owner state and assigned permissions
in a consistent SQLite read transaction. Sessions follow current roles. Scoped
tokens additionally intersect their immutable issuance scopes, so promoting a
role cannot broaden an existing token. Rotation cannot reintroduce a scope the
owner no longer holds. Active requests and streams revalidate their required
permission at one-second intervals; each new request is independently checked.
This database work is on the management request path, never ordinary forwarding.

In **Account & Security**, inspect current session/token permissions, create
roles, select permission collections and assign additional roles to accounts.
Readers can inspect; mutation controls reflect current effective permissions.
Revision failures retain drafts. Explicit reload confirms draft discard.
Backend authorization remains authoritative.

Password-change enrollment now retains the current local verifier until its
replacement commits. It uses an independent pending client salt and a one-time
15-minute capability; completion replaces the verifier, advances generation and
revokes earlier sessions/tokens/capabilities atomically. An abandoned draft
cannot remove the last administrator's login. HTTP administrative resets cannot
remove the last enrolled active local administrator; the deliberate local
recovery path retains its separate capability to reset credentials.

Endpoints under `/api/v2/auth` include `GET/POST /roles`, `PUT/DELETE /roles/{id}`
and `GET/PUT /users/{id}/roles`. Deletion takes `?revision=N`; assignment replaces
`{roleIds,revision}`. Own current permissions are also returned by `/me`.
This increment is part of the broader enterprise security phase; secret
isolation, coordinated changes, expanded audits and generic OIDC have separate
implementation and qualification requirements.
