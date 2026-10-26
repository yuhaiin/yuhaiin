#!/usr/bin/env python3
"""Run the real installed-service backup/crash drill in an isolated container."""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rootful', action='store_true',
                        help='use sudo -n podman (for disposable CI runners)')
    parser.add_argument('--skip-image-build', action='store_true')
    args = parser.parse_args()
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
        run(['go', 'test', '-c', '-o', str(test), './cmd/yuhaiin'], env=environment)
        try:
            # Private container networking/cgroups; no host data directory,
            # host service socket or host PID namespace is mounted.
            run([*runtime, 'run', '-d', '--privileged', '--systemd=always',
                 '--name', name, '--stop-timeout', '1', image, '/sbin/init'])
            run([*runtime, 'exec', name, 'mkdir', '-p', '/app'])
            run([*runtime, 'cp', str(executable), name + ':/app/yuhaiin'])
            run([*runtime, 'cp', str(test), name + ':/app/drill.test'])
            run([*runtime, 'exec', '-e', 'YUHAIIN_RECOVERY_SYSTEMD_DRILL=1', name,
                 '/app/drill.test', '-test.run=^TestInstalledRecoveryMaintenance$',
                 '-test.v', '-test.timeout=4m'], timeout=300)
        except Exception:
            # Fixture enrollment completes before starting the service, so the
            # journal contains no bootstrap capability or private backup key.
            subprocess.run([*runtime, 'exec', name, 'journalctl', '--no-pager',
                            '-u', 'yuhaiin.service', '-u', 'yuhaiin-recovery-*',
                            '-n', '120'], check=False)
            raise
        finally:
            subprocess.run([*runtime, 'rm', '-f', name], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
