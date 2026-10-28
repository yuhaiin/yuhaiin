# Installed-service recovery drill

Run `python3 scripts/bench/recovery-maintenance/run.py` with working Podman.
The default uses rootless Podman; `--rootful` selects `sudo -n podman` on a
disposable CI runner. It builds a systemd image, the actual production executable
and a dedicated test binary. Only the generated container is removed afterwards;
the image remains cached. No host service/socket/data/PID namespace is mounted.
The fixture requires a container runtime that can run systemd with private
cgroups. Image package installation is the only network dependency; all scenario
traffic uses local listeners inside the container.

The drill seeds initialized management credentials, starts a real
`yuhaiin.service`, and requests a full encrypted S3 backup through its actual
HTTPS management API. It requires a changed service PID, verified S3 readback,
authenticated manifest verification using the private backup identity, and an
exact ciphertext download. A disk-backed local object server survives the
service stop; no public S3 provider or real credential is used.

A second backup includes a sparse 1 GiB asset to create a real capture window.
The test kills the independent maintenance helper while the source service is
stopped and the job is capturing. The transient unit's `ExecStopPost` must start
the service even though Go defers cannot run. The server must report the job as
interrupted without adopting a partial archive, and the existing management
session must still work. This is correctness/fault injection, not a performance
or WAN-throughput measurement. Neither test output nor the journal collector
prints the private backup identity or management session token.

The same drill uploads its actual encrypted archive through authenticated HTTPS,
rejects a read-only upload, previews its full inventory without changing the
service PID and confirms removal of private staging on discard. This qualifies
Web import/preview. A final scenario changes the live configuration and performs
a confirmed Web restore of the actual encrypted archive, requiring a changed
service PID, restored configuration/authentication and a committed startup
transaction. Missing consent and read-only activation are rejected. This does
not qualify safe-update rollback.

The same live flow also restores a clone, requiring a fresh instance ID, a new
self-signed management certificate, new administrator initialization and rejection
of the old session. Failure diagnostics redact the newly issued local setup
capability before printing service journals; `test_runner.py` covers that guard.


For a real large offline create/restore/startup measurement, run with
`--asset-mib 256` (bounded to 0–1024 MiB). CI enables this case. The test writes
markers into a sparse source asset, streams its full contents into real staging
and ciphertext, changes content without changing size, and verifies restored
SHA-256 plus the exact transaction's startup commit and existing management
session. A fresh Python parent measures one CLI child's RSS, separately for
creation and restoration with a soft 64 MiB Go target. Fixture generation,
online preview, final hash, server/helper RSS and page cache are excluded.

The reported maintenance window begins before explicit Stop and ends at actual
HTTPS readiness; restore also requires startup commit. It includes the manual
reset of the fixture's rapid-restart burst counter, and does not disable service
start-rate protection. The preceding Web helper must be inactive, including its
ExecStopPost, before a new operator-controlled Stop starts. `--recovery-only`
omits building/running future-schema update scenarios for size comparisons;
the ordinary runner retains all those scenarios.

See the [measurements and limitations](../../../docs/managed-recovery-backups.md#capture-space-and-real-maintenance-measurements).
