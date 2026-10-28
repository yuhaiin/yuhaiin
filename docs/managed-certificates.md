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
  and certificate references. The last two provider tables are storage only;
  automated DNS-01 presentation is not implemented yet.
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

No private-material read endpoint exists. Private wrappers redact ordinary Go
formatting and JSON serialization. Configuration export excludes all new private
tables. Existing coordinated full SQLite snapshots include the material; their
encryption and external-key requirements remain unchanged. A binary supporting
only schema 23 refuses schema 24; database downgrade is not an update rollback.

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

Foundation validation: all 161 Go test packages pass; the related manager/store/
SQLite/archive/CLI tests pass with both SQLite drivers, related race suites pass,
`go fix ./...` makes no changes, and golangci-lint reports zero issues. The real
isolated systemd runner also passes schema 24-to-25 startup, post-migration
readiness failure, helper SIGKILL and paired CLI recovery back to schema 24.
These are backend checks; no certificate-management frontend is delivered yet.

## Remaining lifecycle integration

Automatic DNS-01 with scoped credentials and exact-record cleanup, renewal/ARI
scheduling and bounded backoff, management permissions/RPC, certificate metrics
and events, Management/Gateway references and hot-reload wiring, clone-restore
renewal ownership, EN/JA/KO responsive management UI and full restart/failure
qualification are still required. These foundation tests do not establish that
the complete ACME feature is ready for deployment.
