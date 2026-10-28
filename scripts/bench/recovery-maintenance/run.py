#!/usr/bin/env python3
"""Run the real installed-service backup/crash drill in an isolated container."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid


def redact_journal(text):
    # Clone startup intentionally emits a local one-time setup capability.
    # Public CI failure diagnostics must never publish that capability.
    return re.sub(r'(Initialization code: )[^\r\n]+', r'\1[redacted]', text)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rootful', action='store_true',
                        help='use sudo -n podman (for disposable CI runners)')
    parser.add_argument('--skip-image-build', action='store_true')
    parser.add_argument('--asset-mib', type=int, default=0,
                        help='also measure real offline capture/restore and service restart with 1–1024 MiB')
    parser.add_argument('--recovery-only', action='store_true',
                        help='run capture/restore resources without repeating protected-update scenarios')
    parser.add_argument('--user-session', action='store_true',
                        help='exercise an unprivileged lingering systemd user service')
    args = parser.parse_args()
    if not 0 <= args.asset_mib <= 1024:
        parser.error('--asset-mib must be between 0 and 1024')
    root = Path(__file__).resolve().parents[3]
    runtime = ['sudo', '-n', 'podman'] if args.rootful else ['podman']
    image = 'localhost/yuhaiin-recovery-systemd-test'
    name = 'yuhaiin-recovery-systemd-' + uuid.uuid4().hex[:12]

    def run(command, **kwargs):
        return subprocess.run(command, cwd=root, check=True, text=True, **kwargs)

    if not args.skip_image_build:
        run([*runtime, 'build', '-t', image, '-f',
             'scripts/bench/recovery-maintenance/Containerfile',
             'scripts/bench/recovery-maintenance'])
    with tempfile.TemporaryDirectory(prefix='yuhaiin-recovery-maintenance-') as tmp:
        executable, test = Path(tmp, 'yuhaiin'), Path(tmp, 'drill.test')
        environment = dict(os.environ, CGO_ENABLED='0')
        run(['go', 'build', '-o', str(executable), './cmd/yuhaiin'], env=environment)
        run(['go', 'run', './cmd/update-metadata', '-binary', str(executable),
             '-os', 'linux', '-arch', 'amd64'], env=environment)
        catalog = json.loads(Path(str(executable) + '.update.json').read_text())
        next_schema = catalog['schemas']['configuration'][-1]['version'] + 1
        run(['go', 'test', '-c', '-o', str(test), './cmd/yuhaiin/internal/servicehost'], env=environment)
        # Build real future-schema executables and their matching descriptors.
        # Go overlays keep fault injection out of all production source files.
        fixtures = []
        migration_path = root / 'pkg/storage/sqlite/migrations.go'
        migrated = migration_path.read_text().rsplit('\n}', 1)[0] + (
            '\n{Version: ' + str(next_schema) + ', Name: "protected_update_drill", '
            'Statements: []string{`INSERT INTO metadata(key,value) '
            "VALUES('protected_update_drill','migrated')`}},\n}\n")
        migration_overlay = Path(tmp, 'migrations.go')
        migration_overlay.write_text(migrated)
        health_path = root / 'pkg/app/recovery_health.go'
        for fixture_name, fail in ([] if args.recovery_only else [('update-healthy', False), ('update-failed', True)]):
            replacements = {str(migration_path): str(migration_overlay)}
            if fail:
                health_overlay = Path(tmp, 'failed_health.go')
                prefix, suffix = health_path.read_text().rsplit('return nil', 1)
                health_overlay.write_text(prefix + 'return errors.New("injected readiness failure after real migration")' + suffix)
                replacements[str(health_path)] = str(health_overlay)
            overlay = Path(tmp, fixture_name + '-overlay.json')
            overlay.write_text(json.dumps({'Replace': replacements}))
            binary = Path(tmp, fixture_name)
            run(['go', 'build', '-overlay', str(overlay), '-o', str(binary), './cmd/yuhaiin'], env=environment)
            run(['go', 'run', '-overlay', str(overlay), './cmd/update-metadata',
                 '-binary', str(binary), '-os', 'linux', '-arch', 'amd64'], env=environment)
            fixtures.extend([binary, Path(str(binary) + '.update.json')])
        user_args = []
        try:
            # Private container networking/cgroups; no host data directory,
            # host service socket or host PID namespace is mounted.
            run([*runtime, 'run', '-d', '--privileged', '--systemd=always',
                 '--name', name, '--stop-timeout', '1', image, '/sbin/init'])
            run([*runtime, 'exec', name, 'mkdir', '-p', '/app'])
            run([*runtime, 'cp', str(executable), name + ':/app/yuhaiin'])
            run([*runtime, 'cp', str(test), name + ':/app/drill.test'])
            for fixture in fixtures:
                run([*runtime, 'cp', str(fixture), name + ':/app/' + fixture.name])
            if args.user_session:
                run([*runtime, 'exec', name, 'useradd', '-m', '-u', '1500', 'recoverytest'])
                run([*runtime, 'exec', name, 'chown', '-R', '1500:1500', '/app'])
                run([*runtime, 'exec', name, 'loginctl', 'enable-linger', 'recoverytest'])
                user_args = ['--user', '1500:1500', '-e', 'HOME=/home/recoverytest',
                             '-e', 'XDG_RUNTIME_DIR=/run/user/1500',
                             '-e', 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1500/bus']
                deadline = time.monotonic() + 15
                while subprocess.run([*runtime, 'exec', *user_args, name, 'systemctl', '--user', 'show-environment'],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('lingering user manager did not become ready')
                    time.sleep(0.1)
                run([*runtime, 'exec', *user_args, name, 'systemctl', '--user', 'start', 'dbus.socket'])
            test_pattern = '^TestInstalled(RecoveryMaintenance|UserRecoveryAdmission)$' if args.recovery_only else '^TestInstalled(RecoveryMaintenance|ProtectedUpdate|UserRecoveryAdmission)$'
            run([*runtime, 'exec', *user_args, '-e', 'YUHAIIN_RECOVERY_SYSTEMD_DRILL=1',
                 '-e', f'YUHAIIN_RECOVERY_SYSTEMD_USER={int(args.user_session)}',
                 '-e', f'YUHAIIN_RECOVERY_ASSET_MIB={args.asset_mib}', name,
                 '/app/drill.test', '-test.run=' + test_pattern,
                 '-test.v', '-test.timeout=8m'], timeout=540)
        except Exception:
            journal = subprocess.run([*runtime, 'exec', name, 'journalctl', '--no-pager',
                            '-u', 'yuhaiin.service', '-u', 'yuhaiin-recovery-*',
                            '-u', 'yuhaiin-restore-*', '-u', 'yuhaiin-protected-update-*', '-n', '180'], check=False,
                            capture_output=True, text=True)
            print(redact_journal(journal.stdout))
            if args.user_session:
                journal = subprocess.run([*runtime, 'exec', *user_args, name, 'journalctl', '--user', '--no-pager', '-n', '180'], check=False, capture_output=True, text=True)
                print(redact_journal(journal.stdout))
            raise
        finally:
            subprocess.run([*runtime, 'rm', '-f', name], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
