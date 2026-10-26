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
