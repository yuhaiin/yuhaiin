# Configuration secrets in managed deployments

The optional management identity module masks reusable inline credentials in
configuration responses, including responses to administrators. Local/native
callers without that module retain their existing behavior. No management store
or request authorization is added to network forwarding.

## Permissions

Existing configuration read/write capabilities still select the resource.
`secrets:manage` additionally permits changing inline passwords, private keys,
subscription capability URLs and other annotated secret fields. `secrets:read`
permits explicit retrieval. These capabilities are independent: an operator can
install a credential supplied by its owner without being able to read other
stored credentials. Outbound `credentialRef` values remain references; ordinary
configuration reads never resolve them into authentication material.

`system:execute` additionally protects TUN lifecycle hooks, native library paths
and backup restoration. `security:write` protects changes to trusted management
UI Origins. Neither ordinary settings write access nor secret management alone
permits changing that trust boundary. Scoped tokens keep their issuance scopes;
adding these permissions to a role does not expand existing tokens.

The typed annotations cover node/inbound protocol credentials, private TLS/SSH/
WireGuard/Reality material, backup credentials, Gateway header values and private
bodies, and subscription/publication capability fields. URL user information or
query strings are hidden for route sources, registry metadata, resolver hosts,
Gateway addresses and other annotated URLs. An arbitrary secret placed in an
unannotated public name, arbitrary path or application payload cannot be inferred
reliably; use designated credential fields. Full Nebula client YAML is private
because it can contain embedded PKI keys.

## Editing masked fields

A masked field contains an opaque preservation reference, not an empty password.
Clients must return it unchanged when saving unrelated settings. Server-side
merging occurs against the current resource within the existing configuration
write transaction (or Gateway's revision-checked configuration lock). It resolves
before validation and before runtime publication. Removing or replacing a private
field requires secret management permission.

References bind the resource type/ID, source field path and an opaque keyed
revision of its current configuration. Reordering repeated protocol layers with
secret management permission resolves their original values, rather than copying
another layer's password by array position. Cross-resource references, forged
references and stale revisions fail with HTTP 409. Restarting the process changes
the reference key; reload an open editor after restart or a conflicting save.
No password hash is exposed as a public revision. The reserved legacy bare marker
can only preserve the current field of an existing resource.

The frontend displays saved values as placeholders, retains references in its
draft, and disables protected fields when permission is absent. Copying a masked
node copies masked configuration. It is not a portable credential export. To import
a masked preview, submit the original user-supplied source to
`nodes.import.commit`, together with preview IDs and selected indices. The server
reuses the existing parser and reference rewriting and returns only save outcomes.
Retries retain IDs and select only failed positions. Previewing or committing
never requires returning those credentials to the client.

## Explicit retrieval and diagnostics

A caller with the resource's read permission and `secrets:read` may explicitly
send `X-Yuhaiin-Secret-Access: reveal`. No global reveal mode exists. The frontend
keeps retrieved plaintext in the current editor's temporary state, outside SWR
and browser storage, and clears it on hide, unmount or authentication-scope change.
Pending retrievals are aborted when that scope changes.

Raw profiling/debug data, logs and backup execution also require `secrets:read`:
those formats can contain credentials and cannot be reliably field-redacted.
Backup restoration additionally requires `secrets:manage` and `system:execute`.
Generating/importing Gateway CA material requires `secrets:manage` as well as the
existing Gateway write permission.

Before retrieving secrets, the server writes
`secret.retrieval_authorized` to the private management audit store. Before an
annotated sensitive modification it writes
`configuration.sensitive_change_authorized`, with resource identity and boolean
change categories, never field values or request bodies. Current account and
credential authority is rechecked. If that durable authorization audit fails,
retrieval or mutation fails before exposing or writing the private value.

These are authorization records. The configuration and identity databases may
be separate: these records do not assert that a subsequent configuration commit
succeeded and are not a cross-database transaction. The unified configuration
change journal must supply final commit/activation outcomes. This limitation is
explicit until that workflow is completed.

New remote-download diagnostics omit URL capability paths, user information,
query values and arbitrary remote error response bodies. Previously written logs
and persisted historical diagnostics are not retroactively scrubbed. Protect
existing logs/backups as secrets and apply the installation's retention policy.

Incoming raw nonempty secret fields always require `secrets:manage`, even when
a candidate happens to match the stored value. This prevents configuration saves
from acting as a plaintext-equality guessing oracle. Use the preservation marker
for unrelated edits. Controllers that must pass resolved fields to their storage
layer use a restricted internal second pass, which accepts only unchanged existing
values. This capability is never attached to incoming requests or batches.
Resolver defaults also avoid copying credential-bearing URLs into public names.
