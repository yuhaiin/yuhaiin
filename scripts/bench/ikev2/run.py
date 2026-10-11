#!/usr/bin/env python3
"""Run the IKEv2 client against a real strongSwan server in Podman or Docker."""

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
fixture = root / 'pkg/net/proxy/ikev2/testdata/strongswan'
image = 'localhost/yuhaiin-strongswan-test'
results = {}


def run(*cmd, **kwargs):
    return subprocess.run(cmd, cwd=root, check=True, text=True, **kwargs)


def remove(name):
    subprocess.run([args.runtime, 'rm', '-f', name], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def free_udp_ports(count):
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
            sockets.append(sock)
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def ready(name, marker, probe=None):
    for _ in range(120):
        logs = run(args.runtime, 'logs', name, capture_output=True)
        if marker in logs.stdout + logs.stderr:
            return
        if probe:
            result = subprocess.run(probe, cwd=root, check=False, text=True,
                                    capture_output=True)
            if marker in result.stdout + result.stderr:
                return
        state = run(args.runtime, 'inspect', '--format', '{{.State.Running}}', name,
                    capture_output=True)
        if state.stdout.strip() != 'true':
            raise RuntimeError(logs.stdout + logs.stderr)
        time.sleep(.25)
    raise RuntimeError('server startup timed out: ' + name)


build = run(args.runtime, 'build', '-t', image, str(fixture), capture_output=True)
print('Built ' + image, flush=True)

with tempfile.TemporaryDirectory(prefix='yuhaiin-ikev2-') as directory:
    tmp = Path(directory)
    test_binary = tmp / 'interop.test'
    bench_binary = tmp / 'bench.test'
    host_ike, host_natt = free_udp_ports(2)
    name = 'yuhaiin-ike-' + uuid.uuid4().hex[:10]
    echo = name + '-echo'

    try:
        run(args.runtime, 'run', '-d', '--name', name, '--stop-timeout', '1',
            '--cap-add', 'NET_ADMIN', '-p', f'127.0.0.1:{host_ike}:500/udp',
            '-p', f'127.0.0.1:{host_natt}:4500/udp', image)
        ready(name, 'roadwarrior', [args.runtime, 'exec', name, 'swanctl', '--list-conns'])

        run(args.runtime, 'run', '-d', '--name', echo, '--network=container:' + name,
            '-v', str(fixture / 'echo.py') + ':/echo.py:ro',
            'docker.io/library/python:3.13-alpine', 'python', '-u', '/echo.py')
        ready(echo, 'UDP echo ready')

        run('go', 'test', '-c', '-race', '-tags=ikev2_interop', '-o', str(test_binary),
            './pkg/net/proxy/ikev2/ike')
        test_env = os.environ | {
            'IKEV2_TEST_GATEWAY': '127.0.0.1',
            'IKEV2_TEST_PORT': str(host_ike),
            'IKEV2_TEST_NATT_PORT': str(host_natt),
        }
        print('\n=== strongSwan interop (race instrumented) ===', flush=True)
        tests = run(str(test_binary), '-test.run=TestStrongSwanIKEv2', '-test.v',
                    '-test.timeout=2m', env=test_env, capture_output=True)
        print(tests.stdout, flush=True)
        results['tests'] = tests.stdout

        if args.benchmark:
            run('go', 'test', '-c', '-tags=ikev2_interop', '-o', str(bench_binary),
                './pkg/net/proxy/ikev2/ike')
            print('\n=== strongSwan benchmark (uninstrumented process) ===', flush=True)
            sample = run(str(bench_binary), '-test.run=^$',
                         '-test.bench=BenchmarkStrongSwanIKEv2', '-test.benchtime=1x',
                         '-test.count=3', '-test.timeout=10m', env=test_env,
                         capture_output=True)
            print(sample.stdout, flush=True)
            results['benchmark'] = sample.stdout
    except Exception as exc:
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stdout or '', exc.stderr or '', flush=True)
        else:
            print(str(exc), flush=True)
        logs = subprocess.run([args.runtime, 'logs', '--tail', '80', name], check=False,
                              capture_output=True, text=True)
        print(logs.stdout or logs.stderr or '', flush=True)
        raise
    finally:
        remove(echo)
        remove(name)

if args.output:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        'host': platform.platform(),
        'topology': 'Podman strongSwan EAP-MSCHAPv2 + loopback UDP echo through kernel ESP/NAT-T',
        'results': results,
    }, indent=2) + '\n')
