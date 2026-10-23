# Traffic Access Policy

Traffic authorization is separate from routing. Access Policy decides whether an
external client may reach an original destination and its actual IP endpoint.
The existing route engine then selects how permitted traffic is forwarded. The
condition compiler is shared; route actions never grant authorization.

This completes the access-policy increment of Phase 1, on top of the identity
foundations. User resource governance and enterprise security management remain
separate subsequent phases. See [identity foundations](enterprise-identity.md).

## Migration and protected scope

Management schema 7 adds `traffic_access_config`, an indexed group-reference
table and a trigger preventing deletion of referenced groups. It changes neither
user credentials nor the configuration database. Interrupted migrations roll
back and safely retry at restart. Invalid saved policy JSON or compilation fails
startup; it never resets to an unrestricted policy. Authorization remains in
`management.db`, outside configuration backups and restores.

Existing installations start with authorization disabled, scope all inbounds,
and explicit default deny ready for activation. Authentication modes retain the
migration described in the identity document. To protect a deployment:

1. Create users, groups and independent proxy credentials.
2. Set each supported protected inbound to `users` authentication and assign its
   permitted users. The UI defaults new identity-enabled inbounds to this mode.
3. Add ordered access rules, preferably with default deny. Put identity and
   destination leaves inside an AND condition when both must match.
4. Validate the draft, preview an active credential with an explicit resolved IP,
   then save and activate. Preview uses the active policy, not the draft.
5. Prefer all-inbound scope. With selected-inbound scope, explicitly review every
   other listener. Its traffic remains outside this policy. Gateway direct
   listeners use stable IDs `gateway:<gateway ID>`.

Inside protected scope, **valid authenticated user and credential IDs are always
required**, even with default allow. Anonymous, legacy shared authentication,
invalid/expired identities, missing trusted inbound metadata, unresolved targets
and unsupported evaluation states cannot acquire access. Mixed authentication
does not create an anonymous fallback into protected resources. Direct Gateway
listeners do not authenticate proxy users and are consequently denied when
protected. Use a supported authenticated proxy inbound with Gateway interception
for identity-aware HTTP access. Native TUN and unsupported user authentication
protocols likewise cannot manufacture a trusted user identity.

## Matching and precedence

Rules are evaluated in saved array order. The first matching enabled rule wins;
there is no implicit deny priority or group priority. Put a narrow deny before a
broad allow when that precedence is intended. Multiple group memberships match
the same ordered policy and never depend on Go map iteration order. If no rule
matches, the explicit default action applies after the mandatory identity gate.

Top-level conditions are OR, following existing route expressions. Nested `all`,
`any` and `not` provide AND, OR and NOT. Supported access leaves are user, group,
credential, inbound ID, destination, network (`tcp`/`udp`), port and always.
Destination domains match the original logical destination; exact ASCII/punycode
names and `*.suffix` subdomains are supported, case-insensitively. The wildcard
does not match the suffix apex. CIDRs match the resolved actual endpoint,
including normalized IPv4-mapped IPv6. Domains and CIDRs in one destination leaf
are OR; use two leaves inside AND to require both.

Host/process lists and GeoIP remain available for routing. Access policies reject
those leaves, including inside NOT, instead of interpreting unavailable runtime
state as a permissive match. Time conditions and ICMP access are not supported;
protected ICMP is denied. Domain rules constrain the network endpoint, not HTTP
paths or the content served by an allowed host.

Protected domain targets resolve through the configured resolver before dialing.
Only an authorized IP is passed to the selected outbound. The outbound cannot
resolve that protected hostname again to bypass a resolved-address restriction.
The original domain and actual endpoint remain distinct during evaluation. Gateway
pool keys include the immutable authentication generation, so a membership reload
cannot retain a dial closure bound to a retired identity. A
Gateway request authority and any rewritten upstream are checked separately;
local responses, redirects, connection-pool reuse, direct/default outbound
selection, SkipRoute, DNS interception and recovered FakeIP addresses do not
replace the authorization gate. DNS infrastructure forwarding has an explicitly
empty ingress context and does not acquire a client identity from IP or headers.

## Publication and revocation

Management changes compile and check identity references before persistence.
Configuration, group references, revision and the existing durable management
audit event commit in one private SQLite transaction. Audit failure rolls back
the change. One management mutex covers commit and publication; stale revisions
return 409 without replacing the active snapshot. Compilation or storage failure
leaves the prior active policy intact. This is a single-instance runtime; do not
run competing gateway processes against the same identity database. Revision
checks also prevent a stale second writer from overwriting committed policy.

Publication swaps an immutable snapshot, then rechecks retained authorizations.
Only sessions that lose access close. TCP streams, pending dials, Gateway request
streams and asynchronous DNS operations are revocable. Cached UDP sends and
replies check the current epoch, including the real peer before address rewriting
and again when the reply leaves the queue. Already accepted kernel I/O may finish
during an update; publication is not an atomic cutover of bytes in flight. Every losing TCP stream is cancelled and its I/O deadlines interrupted before
graceful closes run with at most 16 concurrent workers. One TLS close-notify wait
therefore cannot delay interruption of other losing streams. The activation API
joins transport teardown before returning; UDP callbacks signal
shutdown, and queue draining/resource release finishes asynchronously. Local
Gateway writes are interrupted through per-response write deadlines as well as
request cancellation.

UDP keeps a shared full-cone outbound socket per source/migration identity,
credential and inbound. It is never split by destination. An allowed unsolicited
peer is accepted under the current resolved-IP policy; a domain-only allow cannot
invent an original hostname for an unknown peer. If an update denies any retained
target, the owning association closes because its socket is shared. Other users'
and other credentials' associations are unaffected.

Membership changes invalidate the changed owner's credential contexts, requiring
reauthentication for the new immutable membership snapshot. Unchanged owners keep
their contexts. Credential revocation, rotation, expiry and user disablement use
the same cancellation mechanism; management writes reload before success and
external recovery changes are observed by the existing one-second reload.

## Bounds and diagnostics

Limits: 1,024 rules, 1,024 scoped inbound IDs, 4,096 condition nodes and 16,384
condition values across the policy. Port ranges count their expanded values to
bound the existing compiler's memory; omit the port condition for all ports.
Identity/group limits are documented separately. Authorization retains at most
65,536 external sessions, 131,072 exact target keys globally and 1,024 per session.
Capacity exhaustion rejects new authorizations rather than evicting active
security state. Even disabled authorization tracks external lifetimes so later
activation can invalidate pre-existing anonymous/unresolved sessions safely.

Evaluation and cached datagram checks use no SQL or authentication database reads.
Memberships and compiled rules are immutable; a session retains only its subject
and exact authorized endpoints. Global registry locks are confined to admission,
release and publication. Datagrams use a per-association lock and atomic snapshot
reads. Retired snapshots are reclaimed by Go after their sessions release them.

The status endpoint reports tracked sessions and cumulative denied evaluations,
revocations and capacity rejections. Denied candidate IPs can count separately
while resolution selects a later permitted address; these are not distinct users
or connection totals. No user IDs become Prometheus labels. Connection audit JSON
stores the optional policy decision revision/rule and historical group IDs.
Reasons distinguish `access_policy_denied`, `access_policy_revoked` and credential
invalidation. Normal authorization cleanup is not credential revocation. The
existing high-volume traffic audit remains bounded and may drop events; it is
not a lossless compliance ledger.

## Management API and UI

- `GET /api/v2/auth/traffic-access`: active configuration, `traffic-access:read`.
- `GET /api/v2/auth/traffic-access/status`: counters, same permission.
- `POST /api/v2/auth/traffic-access/validate`: structured validation errors,
  `traffic-access:write`, without activation.
- `PUT /api/v2/auth/traffic-access`: revision-checked save and activation, write.
- `POST /api/v2/auth/traffic-access/preview`: active credential ID, inbound ID,
  TCP/UDP, original host:port, resolved IP. Read permission; inspecting another
  owner's credential additionally requires `users:manage`. No DNS query or secret
  is required. Inbound assignment and credential protocol restrictions still apply
  at authentication and are separate from this traffic-policy preview.

Built-in admin gains the new permissions; read-only gains policy read. Previously
issued scoped API tokens retain their existing explicit scopes. A token owner
must issue an appropriately scoped token to manage this feature. Account &
Security reuses the route condition editor, supports ordered rules, explicit
scope/default, validation, conflict-preserving drafts, active-policy preview,
status and historical audit decisions, with EN/JA/KO translations.

See [benchmark evidence](benchmarks/access.md) for topology, measurements and
limits. Native Android receives no management database or authentication-module
dependency; the capability remains optional in core networking.
