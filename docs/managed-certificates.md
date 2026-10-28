# Managed HTTPS certificates

This work extends `pkg/cert` above the existing TLS engines. The application starts the lifecycle worker and exposes permission-gated
management RPC and a responsive certificate page. Management HTTPS can opt in
through its host-owned startup arguments. Live CA renewal advice and its
persisted refresh schedule run in the same worker.
Management self-signed/file TLS, Gateway file termination, Gateway MITM CA and
TLS Auto CA keep their existing behavior. Site certificates never replace a CA
signer or enter the MITM leaf cache.

## Implemented foundation

- Stable certificate resource IDs, revisioned configuration, DNS SANs, explicit
  terms consent, HTTP-01/DNS-01 challenge configuration and public status types.
- Schema 24 in the existing private configuration SQLite: site key pairs, ACME
  account keys/registration URIs, provider credential storage, cleanup receipts
  and certificate references. Public provider projections contain no token;
  token replacement is write-only and ordinary edits retain the current token.
- Durable bounded issuance leases. Competing jobs, expired leases and a request
  using an old configuration revision cannot overwrite a newer job's result.
  Failure completion retains the existing key pair.
- RFC 8555 issuance through the existing `golang.org/x/crypto/acme` dependency.
  Account keys are committed before registration and reused on the next request.
  The caller must inject the governed HTTPS client and a deadline of at most ten
  minutes. CA-directed requests remain on the configured HTTPS origin, redirects
  are rejected and each response is limited to 1 MiB. There is no direct-network
  fallback, extra listener, disabled certificate verification or browser task.
- HTTP-01 token presentation with exact listener/Host/token matching, bounded
  pending entries and cancellation cleanup. The adapter requires an explicitly
  enabled port-80 Gateway. The handler is mounted after the listener source ACL;
  no extra listener is opened and existing HTTP service ownership is preserved.
- Key-pair, chain, server-auth purpose, lifetime and exact requested SAN-set
  validation. A private ACME CA can use explicit public trust PEMs; these roots
  do not change DNS-provider or application-wide HTTP trust.
- Atomic immutable certificate cache. Real TLS connections check expiration,
  SNI and client capabilities. A malformed replacement retains a previously
  verified certificate only if it still satisfies the resource's SAN/trust policy.
  New TLS connections see the replacement; established streams remain usable.
- DNS-01 provider interface and a real Cloudflare DNS API adapter, with an
  explicitly configured zone and scoped bearer token, fixed HTTPS API origin,
  no redirects, bounded responses and no replay of an uncertain create request.
  The challenge owner waits for TXT evidence from an injected governed resolver,
  never merely treats API creation as proof of DNS propagation.
- Durable cleanup receipts committed before record creation. Cleanup checks the
  exact random ownership comment, name, content and record ID. An ambiguous POST
  waits until the operation deadline plus a settling interval before reconciling
  by its unique comment. Failures retain receipts and backoff; another owner's
  TXT is never deleted. A provider/zone cannot be deleted or rebound while used
  by certificates or pending cleanup. Limits: 64 providers, 256 pending receipts,
  1 MiB per API response, one bounded page of cleanup matches.
- One cancellable certificate worker and one timer, persistent issuance/renewal
  deadlines and failure state, stable jitter near 60–75% of certificate lifetime,
  bounded exponential retry and CA/DNS Retry-After handling. Manual renewals have
  a five-minute minimum attempt interval and cannot skip failure backoff. Jobs
  are admitted by earliest due time; configuration/deletion cancel the old job,
  and expired leases recover interrupted attempts after restart. Production
  startup restores the cache before Gateway assembly and starts work only after
  routing/admission is ready. Shutdown cancels work before closing network/SQL owners.

The worker fetches live [RFC 9773 renewal advice](https://www.rfc-editor.org/rfc/rfc9773.html)
after issuance and refreshes it on a persisted Retry-After deadline. Requests use
the governed verified CA transport, the advertised HTTPS origin and 64 KiB JSON
limits; redirects are rejected. Certificate IDs preserve DER serial leading zeros.
No expired or replaced leaf is queried and explanation links are never fetched.
The public resource exposes the window, next check, state and consecutive failures.

Refresh and issuance share the existing durable lease, one worker and one timer.
Advice cannot reset issuance backoff, overwrite a newer revision or resurrect a
deleted resource. Urgent past windows request immediate renewal subject to the
five-minute minimum attempt interval. CA checking intervals are bounded to one
minute–one day; temporary failures use at most five exponential retries, then a
six-hour default. A failed metadata query keeps the current renewal plan and pair.
Unsupported ARI uses the lifetime schedule. `autoRenew=false` permits explicitly
queued initial/manual issuance, then stops periodic advice and automatic renewal.

The existing mature ACME client still owns authenticated account/order protocol.
It does not expose the optional newOrder `replaces` extension; no ARI-specific CA
rate-limit exemption is claimed. Normal issuance limits and backoff always apply.

No private-material read endpoint exists. Private wrappers redact ordinary Go
formatting and JSON serialization. Configuration export excludes all new private
tables. Existing coordinated full SQLite snapshots include the material; their
encryption and external-key requirements remain unchanged. A binary supporting
only schema 23 refuses schema 24; database downgrade is not an update rollback.

Original-instance recovery preserves managed credentials and renewal/cleanup
state. Clone recovery clears site/account private keys, DNS tokens and source
cleanup receipts; retained public resources are marked disabled with automatic
renewal off. An administrator must explicitly re-enroll the new instance. The
clone cannot accidentally delete the source's pending challenge records.

## Deterministic evidence

`pkg/cert/manager/acme_test.go` runs a local HTTPS ACME server which verifies real
ES256 JWS signatures/nonces, follows the HTTP-01 handler, checks the CSR signature
and signs with a local test CA. It exercises first issuance, account reuse,
renewal, live TLS replacement, existing-stream continuity, wrong SNI/SAN,
not-yet-valid/expired certificates, malformed replacements, HTTPS verification,
origin fencing and response memory limits. Store tests cover competing leases,
revision conflicts, retained material, reference protection, secret projections
and inclusion of account keys from live WAL in a coherent recovery snapshot.
Migration tests upgrade an actual schema-23 database without changing its MITM CA.

`dns_issuance_test.go` connects the real ACME client and Cloudflare adapter to
local HTTPS CA/provider servers, verifies the TXT proof and checks exact cleanup.
Provider/service tests cover foreign records, changed ownership, lost create
replies, cleanup failures/restart retries, cancellation, propagation failures,
verified TLS, redirects, response bounds and token redaction. An injected clock
tests lifetime/window selection, backoff, manual rate protection, persisted
restart plans and interrupted-lease recovery. Concurrent managers cannot issue
the same resource, configuration cancels in-flight work, and a failed renewal
retains the old pair. The real encrypted original/clone restore test checks
certificate jobs, private material, account keys, tokens and pending receipts.

## Administration and listener binding

1. Open **Certificates** with `certificates:read`. Mutations require
   `certificates:manage`; existing management session and authorization checks
   apply. No endpoint returns private keys or provider tokens.
2. For DNS-01, add a Cloudflare provider with the explicit authoritative zone ID
   and zone name. Give its token DNS read/write access only to that zone. Leaving
   the token blank on an edit retains the stored credential. Removal/rebinding
   is refused while a certificate or cleanup receipt uses the provider.
3. For HTTP-01, first configure an existing enabled plaintext Gateway on port 80
   and explicitly enable **ACME HTTP-01**. Source ACLs must admit CA validation
   requests. Select that Gateway in the certificate form. Port conflicts remain
   ordinary listener errors; certificate setup never silently replaces a service.
4. Create a resource with its DNS names/SANs, email, accepted CA terms and challenge.
   Start with Let's Encrypt Staging to validate deployment. Staging certificates
   are not publicly trusted; select Production for public use. Custom compatible
   directories require HTTPS; optional public CA roots are scoped to that job.
5. In Gateway TLS termination, select **Managed certificates**, choose one or more
   resource IDs and apply the workspace revision. A pending/expired resource can
   be referenced, but TLS handshakes fail closed until valid material exists.
   SNI must match a referenced valid certificate. Removing/changing a referenced
   resource is guarded in the same SQLite transaction as Gateway configuration.
   Configuration-only imports rebuild deletion guards before listeners publish.
6. The page shows SANs, issuer, expiry, renewal schedule/failure, listener references
   and bounded lifecycle events. **Renew now** queues real backend work subject to
   backoff and rate protection. A failed renewal retains the usable old pair.
   New TLS handshakes use the atomic replacement without restarting the Gateway.

Management HTTPS keeps self-signed/file defaults. To migrate, first issue a valid
resource from the existing interface, then add `-https-certificate-id <resource-id>`
to the installed service and restart. The certificate page exposes this exact
argument and actual references. Use a DNS hostname covered by the certificate.
Do not combine managed mode with file-pair or generated-name flags. Missing,
expired or untrusted material stops startup before HTTP is served; there is no
plaintext or self-signed fallback for an explicitly managed listener. Renewals
use the same atomic cache. An established stream is not interrupted. To return
to host file/self-signed mode, remove the reference argument and restart with
the reviewed original host settings. A deployment which adopted restored startup
settings must also explicitly review `-recovery-startup=false`; ordinary flags do
not silently override restored inputs. ACME resources never replace Gateway MITM
or TLS Auto CA signers. File-based Gateway certificate/key configuration remains
supported and is mutually exclusive with managed IDs on a listener.

CA/provider HTTP and DNS requests use existing routing, admission and traffic
control. No ambient proxy or system Direct fallback is installed. Separate HTTP
transports keep custom CA roots from affecting Cloudflare verification. Startup
fails closed if the governed network path is not ready.

Public RPCs are `certificates.list`, `certificate.save`, `certificate.delete`,
`certificate.renew`, `certificate.provider.save` and `certificate.provider.delete`.
Revision conflicts and references are rejected; mutation bodies are bounded.
Public events retain at most 64 finite-code entries. Prometheus exposes
`yuhaiin_certificates` with fixed state labels,
`yuhaiin_certificate_expiration_min_seconds` and
`yuhaiin_certificate_renewals_total` with success/failure labels. Scrapes read
atomic memory snapshots without SQL or domain/URL/resource-ID labels.

## Management identity, recovery and updates

Managed mode records its resource ID in the authenticated recovery runtime.
The stopped-writer configuration SQLite snapshot owns its material and accounts;
no PEM is copied from an actively written database. Startup binds a private
reference/deletion guard only after validating the current pair. Original-instance
restore preserves the ID and keys; clone restore removes source private material
and uses a new self-signed management identity, with an explicit preview warning.
Recovery startup compares the restored ID as well as TLS/auth/file modes.

The update manifest advertises `managedTLS` support. A target without it is refused
when the observed runtime uses managed management TLS, even if schema catalogs
match. The compatibility read includes committed live WAL without migration.
During a protected update, renewal waits for both internal pinned-listener checks
and the independent helper's completion acknowledgement. Timeout, foreign PID or
changed operation fails startup rather than racing the receipt's certificate pin.

## Application and browser evidence

The application/Gateway/API/store/manager/auth focused and race suites pass,
both SQLite drivers pass, full Go tests pass and golangci-lint reports zero
issues. Gateway tests use actual TLS listeners: a replacement changes the new
connection's certificate while an established stream remains usable; wrong SNI
fails, references block deletion, and configuration-only import repairs guards.
The explicit port-80 HTTP-01 test preserves source ACLs; it skips only if that
port is unavailable. CA/provider protocol tests otherwise use local ephemeral
servers. Application HTTP-client tests verify governed admission, separate trust
roots and no network fallback.

The frontend passes lint, typecheck, translations, style checks, build and all
366 tests in 117 files. Its native-Chrome harness runs the actual backend with
private disposable SQLite at 1440, 360 and 320 pixels. It initializes a real
administrator, saves a provider/resource, reads persisted settings back, observes
a real background CA failure and verifies no public token or horizontal overflow.
The browser harness deliberately uses an unreachable local CA directory, not a
public CA; successful real issuance is covered separately by local signing-CA/
Cloudflare-adapter tests above. Reproduce the browser check from the frontend:

```sh
CERTIFICATES_BACKEND=/path/to/yuhaiin ARTIFACT_DIR=/tmp/certificate-checks \
CHROME_PATH=/path/to/chrome node scripts/check-certificates.mjs
```

The earlier isolated systemd runner also passes schema 24-to-25 startup,
post-migration readiness failure, helper SIGKILL and paired CLI recovery back to
schema 24. Actual CLI subprocess tests additionally cover managed startup/restart, missing
material, ambiguous source flags, encrypted original/clone restore, adopted startup
settings and verified TLS after restoration. Management listener tests cover hot
replacement, retained streams, SNI rejection and reference protection. Update
regressions reject an older capability and require the independent verifier's
acknowledgement. The [requirement matrix](enterprise-reliability-audit.md) records
the exact lifecycle assertions and support boundaries.

## ARI application evidence

Local HTTPS tests verify the RFC ID vector, unsigned GET, Retry-After bounds and
HTTP-date parsing, unsafe origins/redirects, untrusted TLS, invalid/oversized JSON,
past windows, missing headers, cancellation and safe explanation URLs. Injected
clocks exercise persisted refresh/restart plans, urgent replacement without loops,
retained old pairs, issuance/manual backoff, deduplication, configuration/delete
cancellation and interrupted refresh leases. Related race suites pass.

The actual CLI subprocess test now starts the complete application/worker with a
private signed management pair. An explicit blocked routing rule prevents CA
requests; after an explicit test-fixture route change, the governed HTTPS client
reads a local CA directory/advice and publishes real SQLite status. Real restart
and encrypted original/clone restoration preserve/reset the applicable identity
and schedule. No public CA, system resolver or ungoverned fallback is used.

The [three-stage evidence matrix](enterprise-reliability-audit.md) records the
final requirement mapping. Exact-head remote CI is a separate delivery gate;
earlier green commits do not qualify a later head.

Provider wire behavior follows the official [Cloudflare create](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/),
[list](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)
and [delete](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/delete/)
API references. The explicit zone ID avoids account-wide zone discovery permissions.
