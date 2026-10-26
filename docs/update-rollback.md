# Software update history and rollback

The built-in updater for service installations on Linux, macOS, and Windows keeps **the two most recently replaced executable files**. Updates and restorations use the same service-stop, executable-swap, and service-restart helper.

## Storage

Snapshots are stored under the configured yuhaiin data directory:

```text
<data-dir>/
  update/
    versions/
      <sha256>.bin
      <sha256>.json
```

The JSON sidecar records the version, commit, SHA-256 ID, byte size, and snapshot timestamp. The archive directory is private to the service account. When restoring a version, the backend validates its ID and checks the binary's SHA-256 again before staging it next to the installed executable.

Each successful binary replacement archives the outgoing executable, removes the newly active binary from the history if it was previously archived, then keeps only the two newest remaining entries. A failed update does not prune the history. The transient `<executable>.update-backup` still protects the replacement operation itself.

## Web UI

Open **About → Software Update → Previous versions**. Select **Restore** for a history entry and confirm. The page follows the same service restart and version checks as an ordinary update.

Only the **executable** is restored. Existing configuration, SQLite databases, and any migrations are not reverted. A binary downgrade may not be compatible with newer data.

The reliability branch now checks each configuration/management database's
known contiguous migration history, names and metadata version before bootstrap
writes or journal-mode changes. A future, foreign or incomplete schema is
rejected with an incompatibility error instead of silently skipping unknown
versions or applying configuration migrations to an identity database. Known
older prefixes still follow the existing transactional migrations; an empty
database or interrupted empty base bootstrap can initialize normally.

This startup guard does not establish that an arbitrary archived old binary is
safe: older binaries can lack the guard. Updater compatibility negotiation,
automatic pre-update recovery points and post-update rollback coordination are
still pending. Use a matching binary and verified database recovery point when
a migration is incompatible; executable history alone does not reverse it.

## When the service cannot start

The Web UI requires a running server. When an update prevents yuhaiin from starting, use the archived file directly from an administrator shell:

1. Locate the actual installed executable and configured data directory. Use the `.json` sidecar to identify a snapshot, and verify that its binary's SHA-256 matches its filename.
2. Stop the installed yuhaiin service via `systemctl stop yuhaiin` (Linux), the configured launchd service (macOS), or `Stop-Service Yuhaiin` (Windows, elevated PowerShell).
3. Preserve the currently installed executable separately, then copy the selected `<sha256>.bin` **over the installed executable**, keeping the installed path and executable permissions. For example, on Linux: `sudo install -m 0755 /path/to/data/update/versions/<sha256>.bin /path/to/yuhaiin`.
4. Start the service again with its platform service manager and check its logs and health.

On macOS, use the existing launchd plist to boot out and bootstrap the system service while replacing the executable; on Windows, close any processes still holding the executable before copying it. These instructions are for emergency manual recovery only and do not alter the service installation layout.

Do not delete history entries while a replacement or recovery is in progress.
