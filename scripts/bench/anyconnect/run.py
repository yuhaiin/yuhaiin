#!/usr/bin/env python3
"""Run the AnyConnect client against an ocserv server in Podman or Docker."""

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
fixture = root / 'pkg/net/proxy/anyconnect/testdata/ocserv'
image = 'localhost/yuhaiin-ocserv-test'
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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(.25)
            if sock.connect_ex(('127.0.0.1', port)) == 0:
                return
        state = run(args.runtime, 'inspect', '--format', '{{.State.Running}}', name,
                    capture_output=True)
        if state.stdout.strip() != 'true':
            logs = run(args.runtime, 'logs', '--tail', '80', name, capture_output=True)
            raise RuntimeError(logs.stdout + logs.stderr)
        time.sleep(.25)
    raise RuntimeError('ocserv startup timed out')


build = run(args.runtime, 'build', '-t', image, str(fixture), capture_output=True)
print('Built ' + image, flush=True)

with tempfile.TemporaryDirectory(prefix='yuhaiin-anyconnect-') as directory:
    tmp = Path(directory)
    test_binary = tmp / 'interop.test'
    bench_binary = tmp / 'bench.test'
    host_port = free_tcp_port()
    name = 'yuhaiin-ocserv-' + uuid.uuid4().hex[:10]
    echo = name + '-echo'

    try:
        run(args.runtime, 'run', '-d', '--name', name, '--stop-timeout', '1',
            '--cap-add', 'NET_ADMIN', '--device', '/dev/net/tun',
            '-p', f'127.0.0.1:{host_port}:8443/tcp', image)
        ready(name, host_port)

        run(args.runtime, 'run', '-d', '--name', echo, '--network=container:' + name,
            '-v', str(fixture / 'echo.py') + ':/echo.py:ro',
            'docker.io/library/python:3.13-alpine', 'python', '-u', '/echo.py')

        run('go', 'test', '-c', '-race', '-tags=anyconnect_interop', '-o', str(test_binary),
            './pkg/net/proxy/anyconnect')
        test_env = os.environ | {
            'ANYCONNECT_TEST_GATEWAY': '127.0.0.1',
            'ANYCONNECT_TEST_PORT': str(host_port),
        }
        print('\n=== ocserv AnyConnect interop (race instrumented) ===', flush=True)
        tests = run(str(test_binary), '-test.run=TestOcservAnyConnect', '-test.v',
                    '-test.timeout=2m', env=test_env, capture_output=True)
        print(tests.stdout, flush=True)
        results['tests'] = tests.stdout

        if args.benchmark:
            run('go', 'test', '-c', '-tags=anyconnect_interop', '-o', str(bench_binary),
                './pkg/net/proxy/anyconnect')
            print('\n=== ocserv AnyConnect benchmark (uninstrumented) ===', flush=True)
            sample = run(str(bench_binary), '-test.run=^$',
                         '-test.bench=BenchmarkOcservAnyConnect', '-test.benchtime=1x',
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
        remove(echo)
        remove(name)

if args.output:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        'host': platform.platform(),
        'topology': 'Podman ocserv CSTP over TLS + loopback UDP echo through the AnyConnect tunnel',
        'results': results,
    }, indent=2) + '\n')
