# Managed HTTPS certificates

This work extends `pkg/cert` above the existing TLS engines. The application starts the lifecycle worker and exposes permission-gated
management RPC and a responsive certificate page. Management HTTPS resource
binding and live ARI retrieval remain under construction.
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

The worker accepts a validated CA renewal window, but live ARI retrieval and
periodic refresh are not implemented yet. A configured `autoRenew=false` still
allows an explicitly queued initial/manual request, then stops automatic renewal.

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

Management HTTPS retains its current self-signed/file behavior; its managed
resource binding is not yet available. ACME resources never replace Gateway MITM
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
363 tests in 116 files. Its native-Chrome harness runs the actual backend with
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
schema 24. These checks do not establish complete certificate deployment readiness.

## Remaining lifecycle integration

Management HTTPS managed-resource binding, live ARI retrieval/periodic refresh,
complete application certificate restart/failure qualification and exact-head
remote CI are still required. The worker currently accepts a validated CA renewal
window supplied by its caller and otherwise schedules from certificate lifetime.

Provider wire behavior follows the official [Cloudflare create](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/),
[list](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)
and [delete](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/delete/)
API references. The explicit zone ID avoids account-wide zone discovery permissions.
