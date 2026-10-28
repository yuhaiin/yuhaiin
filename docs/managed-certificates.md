# Managed HTTPS certificates

This work extends `pkg/cert` above the existing TLS engines. The lifecycle is
under construction; it is not yet available through management RPC or the UI.
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
  enabled port-80 Gateway; actual Gateway mounting remains to be connected.
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
  and expired leases recover interrupted attempts after restart. These owners
  are not yet started by production application assembly.

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

Foundation validation: all 161 Go test packages pass; the related manager/store/
SQLite/archive/CLI tests pass with both SQLite drivers, related race suites pass,
`go fix ./...` makes no changes, and golangci-lint reports zero issues. The real
isolated systemd runner also passes schema 24-to-25 startup, post-migration
readiness failure, helper SIGKILL and paired CLI recovery back to schema 24.
These are backend checks; no certificate-management frontend is delivered yet.

The DNS/worker follow-up passes all 163 Go test packages, related manager/DNS/
store/contract/recovery race suites, both SQLite drivers, formatting, unchanged
Go fixes and zero lint issues. The encrypted original/clone identity regression
also passes three race repetitions. Production application lifecycle assembly is
still pending; these tests exercise the actual component network/persistence
paths without claiming deployed listener or browser integration.

## Remaining lifecycle integration

Production assembly/governed client and DNS wiring, live ARI retrieval/refresh,
management permissions/RPC, certificate metrics/events, Management/Gateway
references and hot-reload wiring, EN/JA/KO responsive management UI and complete
application restart/failure qualification are still required. These component
tests do not establish that the complete ACME feature is ready for deployment.

Provider wire behavior follows the official [Cloudflare create](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/),
[list](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)
and [delete](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/delete/)
API references. Give the token DNS record read/write access only to the configured
zone. The explicit zone ID avoids account-wide zone discovery permissions.
