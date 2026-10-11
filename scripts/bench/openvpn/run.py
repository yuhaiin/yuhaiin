#!/usr/bin/env python3
"""Run real-server interop and optional benchmarks with Podman or Docker."""
import argparse
import json
import os
import pathlib
import platform
import subprocess
import tempfile
import time
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--runtime', default='podman', choices=['podman', 'docker'])
parser.add_argument('--benchmark', action='store_true')
parser.add_argument('--output', type=pathlib.Path)
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parents[3]
image = 'localhost/yuhaiin-openvpn-test'

def run(*cmd, **kw):
    return subprocess.run(cmd, cwd=root, check=True, text=True, **kw)

run(args.runtime, 'build', '-t', image, str(root/'pkg/net/proxy/openvpn/testdata'))
# Build once: each test/benchmark runs in its own client process while the
# server and echo workers stay in a separate container.
with tempfile.TemporaryDirectory(prefix='yuhaiin-openvpn-') as directory:
    tmp = pathlib.Path(directory)
    binary = tmp / 'interop.test'
    run('go', 'test', '-c', '-race', '-tags', 'openvpn_interop', '-o', str(binary),
        './pkg/net/proxy/openvpn')
    cases = [
        ('udp', 'tls-crypt', 'AES-256-GCM', False, 3600),
        ('tcp', 'tls-crypt', 'AES-128-GCM', False, 3600),
        ('udp', 'tls-auth', 'CHACHA20-POLY1305', False, 3600),
        ('udp', 'none', 'AES-256-GCM', True, 3600),
        ('udp', 'tls-crypt', 'AES-256-GCM', False, 2),
    ]
    results = []
    for index, (network, protection, cipher, no_cert, reneg) in enumerate(cases):
        name = 'yuhaiin-ovpn-'+uuid.uuid4().hex[:12]
        state = tmp / str(index)
        state.mkdir()
        print(f'\n=== {network} / {protection} / {cipher} / no_cert={no_cert} ===', flush=True)
        try:
            run(args.runtime, 'run', '-d', '--name', name, '--cap-add', 'NET_ADMIN',
                '--device', '/dev/net/tun', '-p', '127.0.0.1::1194/'+network,
                '-v', str(state)+':/state:Z', '-e', 'OVPN_NETWORK='+network,
                '-e', 'OVPN_PROTECTION='+protection, '-e', 'OVPN_CIPHER='+cipher,
                '-e', 'OVPN_NO_CERT='+str(int(no_cert)), '-e', 'OVPN_RENEG='+str(reneg), image)
            for _ in range(120):
                logs = run(args.runtime, 'logs', name, capture_output=True)
                if 'Initialization Sequence Completed' in logs.stdout+logs.stderr:
                    break
                inspect = run(args.runtime, 'inspect', '--format', '{{.State.Running}}', name,
                              capture_output=True)
                if inspect.stdout.strip() != 'true':
                    raise RuntimeError(logs.stdout+logs.stderr)
                time.sleep(.25)
            else:
                raise RuntimeError('server startup timed out')
            published = run(args.runtime, 'port', name, '1194/'+network, capture_output=True)
            gateway = published.stdout.strip().splitlines()[0]
            env = os.environ | {
                'OPENVPN_TEST_STATE': str(state), 'OPENVPN_TEST_GATEWAY': gateway,
                'OPENVPN_TEST_NETWORK': network, 'OPENVPN_TEST_PROTECTION': protection,
                'OPENVPN_TEST_CIPHER': cipher, 'OPENVPN_TEST_NO_CERT': str(int(no_cert)),
                'OPENVPN_TEST_SERVER_REKEY': str(int(reneg == 2)),
            }
            tests = run(str(binary), '-test.run=TestOfficialOpenVPN', '-test.v',
                        '-test.timeout=90s', env=env, capture_output=True)
            print(tests.stdout, flush=True)
            result = dict(network=network, protection=protection, cipher=cipher,
                          no_cert=no_cert, renegotiate_seconds=reneg, tests=tests.stdout)
            if args.benchmark and reneg != 2:
                # Race instrumentation distorts throughput. Compile a separate
                # uninstrumented process for benchmark measurements.
                bench = tmp / 'bench.test'
                if not bench.exists():
                    run('go', 'test', '-c', '-tags', 'openvpn_interop', '-o', str(bench),
                        './pkg/net/proxy/openvpn')
                sample = run(str(bench), '-test.run=^$', '-test.bench=BenchmarkOfficialOpenVPN',
                             '-test.benchtime=2s', '-test.count=3', '-test.timeout=3m',
                             env=env, capture_output=True)
                print(sample.stdout, flush=True)
                result['benchmark'] = sample.stdout
            results.append(result)
        except subprocess.CalledProcessError as exc:
            print(exc.stdout or '', exc.stderr or '', flush=True)
            subprocess.run([args.runtime, 'logs', name], check=False)
            raise
        finally:
            subprocess.run([args.runtime, 'rm', '-f', '--time', '0', name], check=False,
                           stdout=subprocess.DEVNULL)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(dict(host=platform.platform(), results=results), indent=2)+'\n')
