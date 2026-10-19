# Local certificate authority

The Gateway CA is a separate trust identity from TLS Auto and ordinary HTTPS
listener certificates. **Generate local CA** creates ECDSA P-256 with
`CN=Yuhaiin Local CA, O=Yuhaiin`, a 10-year root lifetime, and signing key usage.
Leaf certificates have DNS/IP SANs, ServerAuth EKU, random serials, a 30-day
lifetime capped by the CA expiry, and a small NotBefore allowance for clock skew.

SQLite persists the exact root DER/PEM and PKCS#8 signer. Restarting does not
regenerate or re-sign the root. Status returns its SHA-256 fingerprint, subject,
validity, public PEM, CA revision, and leaf-cache size. The 512-entry cache is
owned by one CA version, keys by hostname/algorithm, coalesces concurrent misses,
and refreshes leaves expiring within an hour. Rotation replaces the entire cache.
TLS Auto uses the same issuance and bounded cache primitives with its independent
configured CA and domain policy.

The ordinary configuration/status/backup APIs never return the CA private key.
Import is a write-only authenticated management operation; it validates CA signing
capability, validity and key pairing. Accepted key format is PKCS#8 PEM. Public
root download in the UI is built from `certificatePem`; it contains no signer.
Rotation requires an explicit UI confirmation and current CA revision. Existing
clients must trust the replacement root; established TLS sessions retain their
negotiated security state until closed.

SQLite databases and existing WAL/SHM/journal sidecars are restricted to mode
0600 on supporting platforms. The signer is protected by OS access controls and
is not encrypted by a second application key. Protect the data directory and
backups accordingly. Platform-specific hardware-backed key stores are not
implemented. Remote management should use TLS and existing authentication.

Download the public certificate and verify its displayed fingerprint before
installing it. Windows uses Trusted Root Certification Authorities; macOS uses
Keychain Access and explicit SSL trust; Linux uses the distribution's local CA
directory/trust-update tool (browsers may have separate stores). Android/iOS use
certificate/profile settings and, where required, full trust. Applications may
reject user CAs regardless of system installation. The app never installs trust
automatically. Installing a root does not itself enable MITM.

For safe recovery of the same identity, stop the service and take an access-
restricted SQLite snapshot, including `gateway_ca`. For example:

```sh
umask 077
sqlite3 /path/to/yuhaiin/state.db ".backup '/secure/yuhaiin-state.db'"
chmod 600 /secure/yuhaiin-state.db
```

Restore the database while the service is stopped, then verify the public
fingerprint before allowing clients to reconnect. Do not copy only the main
database from a running WAL database. Ordinary exported JSON configuration
backups intentionally omit the signer; they cannot restore CA identity by
themselves. Alternatively import the original CA certificate/key from an already
secured administrator backup. There is no private-key download endpoint.
