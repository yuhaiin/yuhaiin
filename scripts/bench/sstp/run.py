#!/usr/bin/env python3
"""Run the SSTP client against a SoftEther server in Podman or Docker."""

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
parser.add_argument('--image', default='docker.io/siomiz/softethervpn:4.43')
args = parser.parse_args()

root = Path(__file__).resolve().parents[3]
results = {}


def run(*cmd, **kwargs):
    return subprocess.run(cmd, cwd=root, check=True, text=True, **kwargs)


def remove(name):
    subprocess.run([args.runtime, 'rm', '-f', name], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def free_tcp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def ready(name, port):
    for _ in range(120):
        logs = run(args.runtime, 'logs', name, capture_output=True)
        if '[initial setup OK]' in logs.stdout + logs.stderr:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(.25)
                if sock.connect_ex(('127.0.0.1', port)) == 0:
                    return
        state = run(args.runtime, 'inspect', '--format', '{{.State.Running}}', name,
                    capture_output=True)
        if state.stdout.strip() != 'true':
            raise RuntimeError(logs.stdout + logs.stderr)
        time.sleep(.25)
    raise RuntimeError('SoftEther startup timed out')


with tempfile.TemporaryDirectory(prefix='yuhaiin-sstp-') as directory:
    test_binary = Path(directory) / 'interop.test'
    bench_binary = Path(directory) / 'bench.test'
    host_port = free_tcp_port()
    name = 'yuhaiin-sstp-' + uuid.uuid4().hex[:10]
    echo_name = name + '-echo'

    try:
        run(args.runtime, 'run', '-d', '--name', name, '--stop-timeout', '1',
            '--cap-add', 'NET_ADMIN', '--device', '/dev/net/tun',
            '-p', f'127.0.0.1:{host_port}:443/tcp',
            '-e', 'SPW=yuhaiin-test-admin', '-e', 'HPW=yuhaiin-test-hub',
            '-e', 'USERS=alice:test-password', args.image)
        ready(name, host_port)
        run(args.runtime, 'run', '-d', '--name', echo_name,
            '--network=container:' + name,
            '-v', str(root / 'pkg/net/proxy/softether/testdata/echo.py') + ':/echo.py:ro',
            'docker.io/library/python:3.13-alpine', 'python', '/echo.py')
        echo_ip = run(args.runtime, 'exec', echo_name, 'python', '-c',
                      'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);'
                      's.connect(("1.1.1.1",53));print(s.getsockname()[0])',
                      capture_output=True).stdout.strip()

        run('go', 'test', '-c', '-race', '-tags=sstp_interop', '-o', str(test_binary),
            './pkg/net/proxy/sstp')
        test_env = os.environ | {
            'SSTP_TEST_GATEWAY': '127.0.0.1',
            'SSTP_TEST_PORT': str(host_port),
            'SSTP_TEST_ECHO_IP': echo_ip,
        }
        print('\n=== SoftEther SSTP interop (race instrumented) ===', flush=True)
        tests = run(str(test_binary), '-test.run=TestSoftEtherSSTP', '-test.v',
                    '-test.timeout=2m', env=test_env, capture_output=True)
        print(tests.stdout, flush=True)
        results['tests'] = tests.stdout

        if args.benchmark:
            run('go', 'test', '-c', '-tags=sstp_interop', '-o', str(bench_binary),
                './pkg/net/proxy/sstp')
            print('\n=== SoftEther SSTP benchmark (uninstrumented) ===', flush=True)
            sample = run(str(bench_binary), '-test.run=^$',
                         '-test.bench=BenchmarkSoftEtherSSTP', '-test.benchtime=3x',
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
        remove(echo_name)
        remove(name)

if args.output:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        'host': platform.platform(),
        'topology': 'Podman SoftEther MS-SSTP over TLS with PPP/MS-CHAPv2',
        'results': results,
    }, indent=2) + '\n')
