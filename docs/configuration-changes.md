# Configuration changes

The optional management server provides a bounded, single-instance workflow:
edit an existing form, **Stage and preview**, inspect field differences, validate,
then commit and activate. Account & Security contains draft/history filters,
actor attribution, activation inspection, draft deletion and rollback preparation.
Rollback produces a new draft; it never commits automatically.

## Ownership and atomicity

Each change owns **one resource in one database**. Supported private identity
resources are traffic groups, custom roles, role assignments, traffic access,
identity resource policies, identity providers and audit settings. Configuration
resources are routing rules, routing defaults, routing lists and routing order.
A routing rule includes its existing private local matching lists. Transferring
private matching data into a separately shared list uses the existing direct
editor; a staged rule cannot combine that ownership transfer with its rule edit.

There is no multi-resource or cross-database bundle endpoint. References require
prerequisites to exist; create a group before staging a policy that uses it.
A request naming the wrong store is rejected. This intentionally avoids a
partially committed access/RBAC bundle and makes no two-phase commit claim.

The shared `pkg/security/configchange` adapter has no management authentication
or networking dependency. Existing owner mutators perform typed validation,
reference checks, current authorization and revision checks. Their transaction
writes the target and journal entry together. Validation rolls this transaction
back and publishes no runtime configuration. Existing direct edits also record
history when called through managed HTTP; local/native callers retain their
existing behavior without history/authentication initialization.

The management database uses `synchronous=FULL`. The configuration database also
uses FULL while the managed workflow is enabled. The routing pipeline locks the
runtime before opening a target transaction, prefetches remote sources before
that transaction, prepares a complete candidate against its uncommitted data,
then commits target, journal and applied snapshot marker together. Only after
successful commit does it install the prepared matcher/configuration. Invalid,
incomplete or unpersisted candidates leave the active routing snapshot intact.
An old broken source can be removed; required candidate sources must be usable.
Cached remote content is prepared control data, not part of the SQL transaction.

Identity policy owners retain their existing prepare/commit/publish behavior.
Group reload failure clears the published group revision and fails protected
access closed; history can report a committed change whose activation is not
current. Activation inspection reports active, saved, pending, removed,
superseded or unavailable, rather than assuming a successful HTTP save proves
that a resource remains active forever. A later unrelated routing save can make
its global activation pending until the next apply.

## Permissions, secrets and conflicts

Workflow inspection requires `configuration:read` plus that resource's read
permission; mutation additionally requires `configuration:write` and its write
permissions. Role assignments also require `users:manage`. Rollback adds
`configuration:rollback`. Provider configuration retains its browser-session
restriction. An API token must satisfy its owner's current permissions and its
original scopes. Existing built-in read-only semantics are not expanded.

The server rechecks authority before the owning transaction changes data. This
allows an authorized self-demotion to commit, then subsequent requests observe
the reduced authority. For a configuration-store mutation, a separate private
transaction rechecks the actor and durably records **authorization intent**
before the configuration write. That intent is not cross-database commit proof;
the configuration store's same-transaction journal proves its own commit.
Private audit failures abort the authorized mutation. No permission check or
SQLite query is added to the forwarding path.

Public differences exclude reusable proofs and private payloads, including
path-only remote-list URLs. OIDC/client-secret and audit destination/token
changes are represented by safe change flags. Default remote-list reads mask
the entire URL array and remote preview. Signed preservation markers let an
operator edit metadata without reading or replacing the saved URL. Replacing
URLs requires `secrets:manage`; explicit reveal requires `secrets:read` and stays
in the local editor, separate from the editable draft and shared UI cache.
Commit/rollback rechecks secret authority before any private-source request.

The owner transaction compares canonical current data against the staged base;
revision changes, missing references or competing edits reject commit with 409.
Validation is advisory: commit performs these checks again. Drafts remain
available after conflicts, and the UI retains edited values. Runtime refresh
error messages are excluded from list base comparisons. Rollback rebases onto
the current revision while validating current references and grant bounds; it
cannot bypass a newly revoked permission or revive removed users/credentials.

Group deletion keeps its stable-ID tombstone. Only an explicit authorized
rollback can restore that same ID, after checking current active-group,
membership, user and name limits; ordinary group edits cannot restore it.
Routing rule restoration also restores its saved position. Order rollback
requires exactly the currently available IDs, so it never silently drops an
unknown or newly added rule. Provider revision clocks survive deletion, keeping
old in-flight OIDC flows invalid even after restoring provider configuration.
Restoring a provider does not restore deleted account bindings or sessions.

## Persistence, limits and recovery

Configuration schema migration **18** adds `configuration_changes`. Private
management migration **12** adds the same journal and persistent provider
revision clocks, backfilled from current providers. Both migrations are atomic;
interruption leaves the preceding schema and credentials intact. Restart resumes
with saved drafts, history and monotonic provider revisions. The private journal
remains outside ordinary configuration exports and the Android identity-free
runtime.

Each store retains at most 32 live drafts (24-hour lifetime) and 128 commits.
Each private before/after document is limited to 512 KiB; the public before/after
difference is limited to 1 MiB. Oversized changes fail before persistence rather
than truncating a rollback payload. Expired drafts are hidden from listings and
removed on subsequent journal mutations; retention prunes oldest commits.
List responses contain metadata only; inspecting one change loads its safe diff.
Old private values needed for rollback remain in their owning private database,
so filesystem/backup protection applies to journals as to live configuration.
No browser API returns those private rollback documents.

After process interruption, normal owners reload committed policy from their
databases. A draft has no effect. Routing's committed applied marker and saved
snapshot recover together. A failure response after commit can be checked in
history before retrying; an already committed draft cannot be replayed. There
is no distributed coordinator or additional background control service.

## API

All paths below are under `/api/v2/auth`:

| Method | Path | Result |
| --- | --- | --- |
| GET | `/changes/targets` | Authorized resource kinds/stores and mutation capabilities |
| GET | `/changes?kind=group&state=staged` | Bounded, permission-filtered metadata |
| GET | `/changes/{store}/{id}` | Safe diff and current activation state |
| POST | `/changes` | Stage `{store,kind,resourceId,action,payload}` using an existing typed form payload |
| POST | `/changes/{store}/{id}/validate` | Revalidate without persistence/publication |
| POST | `/changes/{store}/{id}/commit` | Revalidate and commit the draft once |
| POST | `/changes/{store}/{id}/rollback` | Prepare a new rollback draft |
| DELETE | `/changes/{store}/{id}` | Discard an uncommitted draft |

Tests cover restart/replay, same-transaction history failures, base conflicts,
current/specialized permissions, self-demotion, provider-session revocation,
secret isolation before download, strict routing activation, concurrent legacy
apply lock ordering, rule-position restoration, missing references and migration
interruption. Benchmarks are documented in [security.md](benchmarks/security.md).
