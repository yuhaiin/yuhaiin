#!/usr/bin/env python3
"""Run the AmneziaWG client against its official userspace engine in Podman."""

import argparse
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import tempfile
import time
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--runtime', choices=('podman', 'docker'), default='podman')
parser.add_argument('--benchmark', action='store_true')
parser.add_argument('--output', type=Path)
args = parser.parse_args()

root = Path(__file__).resolve().parents[3]
fixture = root / 'pkg/net/proxy/amneziawg/testdata/server'
image = 'localhost/yuhaiin-amneziawg-test'
results = {}


def run(*cmd, **kwargs):
    return subprocess.run(cmd, cwd=root, check=True, text=True, **kwargs)


def remove(name):
    subprocess.run([args.runtime, 'rm', '-f', name], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def free_udp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def keypair():
    private = run(args.runtime, 'run', '--rm', '--entrypoint', 'wg', image,
                  'genkey', capture_output=True).stdout.strip()
    public = run(args.runtime, 'run', '--rm', '-i', '--entrypoint', 'wg', image,
                 'pubkey', input=private + '\n', capture_output=True).stdout.strip()
    return private, public


def ready(name):
    for _ in range(120):
        logs = run(args.runtime, 'logs', name, capture_output=True)
        if 'AmneziaWG test server ready' in logs.stdout + logs.stderr:
            return
        state = run(args.runtime, 'inspect', '--format', '{{.State.Running}}', name,
                    capture_output=True)
        if state.stdout.strip() != 'true':
            raise RuntimeError(logs.stdout + logs.stderr)
        time.sleep(.25)
    raise RuntimeError('AmneziaWG server startup timed out')


build = run(args.runtime, 'build', '-t', image, str(fixture), capture_output=True)
print('Built ' + image, flush=True)

server_private, server_public = keypair()
client_private, client_public = keypair()

with tempfile.TemporaryDirectory(prefix='yuhaiin-amneziawg-') as directory:
    test_binary = Path(directory) / 'interop.test'
    bench_binary = Path(directory) / 'bench.test'
    host_port = free_udp_port()
    name = 'yuhaiin-awg-' + uuid.uuid4().hex[:10]

    try:
        run(args.runtime, 'run', '-d', '--name', name, '--stop-timeout', '1',
            '--cap-add', 'NET_ADMIN', '--device', '/dev/net/tun',
            '-p', f'127.0.0.1:{host_port}:51820/udp',
            '-e', f'SERVER_PRIVATE_KEY={server_private}',
            '-e', f'CLIENT_PUBLIC_KEY={client_public}', image)
        ready(name)

        test_env = os.environ | {
            'AMNEZIAWG_TEST_CLIENT_PRIVATE_KEY': client_private,
            'AMNEZIAWG_TEST_SERVER_PUBLIC_KEY': server_public,
            'AMNEZIAWG_TEST_ENDPOINT': f'127.0.0.1:{host_port}',
        }
        run('go', 'test', '-c', '-race', '-tags=amneziawg_interop', '-o', str(test_binary),
            './pkg/net/proxy/amneziawg')
        print('\n=== official AmneziaWG TCP + UDP interop (race instrumented) ===', flush=True)
        tests = run(str(test_binary), '-test.run=TestOfficialAmneziaWGServer', '-test.v',
                    '-test.timeout=2m', env=test_env, capture_output=True)
        print(tests.stdout, flush=True)
        results['tests'] = tests.stdout

        if args.benchmark:
            run('go', 'test', '-c', '-tags=amneziawg_interop', '-o', str(bench_binary),
                './pkg/net/proxy/amneziawg')
            print('\n=== official AmneziaWG benchmark (uninstrumented) ===', flush=True)
            sample = run(str(bench_binary), '-test.run=^$',
                         '-test.bench=BenchmarkOfficialAmneziaWG', '-test.benchtime=1x',
                         '-test.count=3', '-test.timeout=10m', env=test_env,
                         capture_output=True)
            print(sample.stdout, flush=True)
            results['benchmark'] = sample.stdout
    except Exception as exc:
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stdout or '', exc.stderr or '', flush=True)
        else:
            print(str(exc), flush=True)
        logs = subprocess.run([args.runtime, 'logs', '--tail', '100', name], check=False,
                              capture_output=True, text=True)
        print(logs.stdout or logs.stderr or '', flush=True)
        raise
    finally:
        remove(name)

if args.output:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        'host': platform.platform(),
        'topology': 'Podman official AmneziaWG userspace server with matching junk-packet obfuscation and TCP/UDP echo',
        'results': results,
    }, indent=2) + '\n')
