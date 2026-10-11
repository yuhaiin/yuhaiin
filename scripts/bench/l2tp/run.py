#!/usr/bin/env python3
"""Independent userspace L2TP clients against containerized PPP/Linux peers."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--runtime', choices=('podman', 'docker'), default='podman')
parser.add_argument('--ppp', action='store_true', help='also test xl2tpd/pppd; requires accessible /dev/ppp')
parser.add_argument('--benchmark', action='store_true')
parser.add_argument('--output', type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[3]
fixture = root / 'pkg/net/proxy/l2tp/testdata'
results = []


def run(*cmd, **kwargs):
    return subprocess.run(cmd, cwd=root, text=True, check=True, **kwargs)


def remove(name):
    subprocess.run([args.runtime, 'rm', '-f', name], check=False, stdout=subprocess.DEVNULL)


def ready(name, marker):
    for _ in range(240):
        logs = run(args.runtime, 'logs', name, capture_output=True)
        if marker in logs.stdout + logs.stderr:
            return
        state = run(args.runtime, 'inspect', '--format', '{{.State.Running}}', name, capture_output=True)
        if state.stdout.strip() != 'true':
            raise RuntimeError(logs.stdout + logs.stderr)
        time.sleep(.25)
    raise RuntimeError('server startup timed out: ' + name)


def gateway(name):
    return run(args.runtime, 'port', name, '1701/udp', capture_output=True).stdout.strip().splitlines()[0]


run(args.runtime, 'build', '-t', 'localhost/yuhaiin-l2tpv3-test', str(fixture))
if args.ppp:
    run(args.runtime, 'build', '-f', str(fixture/'Dockerfile.ppp'), '-t', 'localhost/yuhaiin-l2tp-ppp-test', str(fixture))

with tempfile.TemporaryDirectory(prefix='yuhaiin-l2tp-') as directory:
    binary = Path(directory) / 'interop.test'
    run('go', 'test', '-c', '-race', '-tags=l2tp_interop', '-o', str(binary), './pkg/net/proxy/l2tp')
    bench = Path(directory) / 'bench.test'
    if args.benchmark:
        run('go', 'test', '-c', '-tags=l2tp_interop', '-o', str(bench), './pkg/net/proxy/l2tp')

    def exercise(label, env, pattern, benchmark):
        env = os.environ | env
        print('\n=== '+label+' ===', flush=True)
        result = dict(case=label)
        tests = run(str(binary), '-test.run='+pattern, '-test.v', '-test.timeout=90s', env=env, capture_output=True)
        print(tests.stdout, flush=True)
        result['tests'] = tests.stdout
        if args.benchmark:
            sample = run(str(bench), '-test.run=^$', '-test.bench='+benchmark+'$', '-test.benchtime=2s',
                         '-test.count=3', '-test.timeout=3m', env=env, capture_output=True)
            print(sample.stdout, flush=True)
            result['benchmark'] = sample.stdout
        results.append(result)

    # SoftEther's raw L2TP server runs entirely in userspace, including SecureNAT.
    name = 'yuhaiin-l2tp-'+uuid.uuid4().hex[:10]
    echo = name+'-echo'
    try:
        run(args.runtime, 'run', '-d', '--name', name, '--cap-add', 'NET_ADMIN', '-p', '127.0.0.1::1701/udp',
            '-e', 'USERS=alice:test-password', '-e', 'SPW=test-admin-password', '-e', 'HPW=test-hub-password',
            'docker.io/siomiz/softethervpn:4.43')
        ready(name, '[initial setup OK]')
        run(args.runtime, 'run', '-d', '--name', echo, '--network=container:'+name,
            '-v', str(root/'pkg/net/proxy/softether/testdata/echo.py')+':/echo.py:ro',
            'docker.io/library/python:3.13-alpine', 'python', '/echo.py')
        target = run(args.runtime, 'exec', echo, 'python', '-c',
                     'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(("1.1.1.1",53));print(s.getsockname()[0])', capture_output=True).stdout.strip()
        for auth in ('pap', 'mschap-v2'):
            exercise('SoftEther / '+auth, {'L2TP_TEST_GATEWAY': gateway(name), 'L2TP_TEST_TARGET': target, 'L2TP_TEST_AUTH': auth}, '^TestOfficialL2TP', 'BenchmarkRealL2TP')
    except subprocess.CalledProcessError as exc:
        print(exc.stdout or '', exc.stderr or '', flush=True)
        subprocess.run([args.runtime, 'logs', name], check=False)
        raise
    finally:
        remove(echo)
        remove(name)

    if args.ppp:
        for auth in ('pap', 'chap-md5', 'mschap-v2'):
            name = 'yuhaiin-l2tp-ppp-'+uuid.uuid4().hex[:10]
            try:
                run(args.runtime, 'run', '-d', '--name', name, '--privileged', '--device=/dev/ppp', '-p', '127.0.0.1::1701/udp',
                    '-e', 'PPP_AUTH='+auth, 'localhost/yuhaiin-l2tp-ppp-test')
                ready(name, 'PPP server ready')
                exercise('xl2tpd / '+auth+' / IPv6CP', {'L2TP_TEST_GATEWAY': gateway(name), 'L2TP_TEST_TARGET': '10.88.0.1',
                         'L2TP_TEST_AUTH': auth, 'L2TP_TEST_IPV6': '1'}, '^TestOfficialL2TP', 'BenchmarkRealL2TP')
            except subprocess.CalledProcessError as exc:
                print(exc.stdout or '', exc.stderr or '', flush=True)
                subprocess.run([args.runtime, 'logs', name], check=False)
                raise
            finally:
                remove(name)

    cases = [
        ('none', '', '', 'none', False, ''),
        ('4-byte cookie', '11223344', 'aabbccdd', 'none', False, ''),
        ('8-byte cookie / sublayer', '1122334455667788', 'aabbccddeeff0011', 'default', False, ''),
        ('dynamic / sublayer', '', '', 'default', True, ''),
        ('dynamic / authenticated', '1122334455667788', '', 'default', True, 'test-tunnel-secret'),
    ]
    for label, local, peer, layer, dynamic, secret in cases:
        name = 'yuhaiin-l2tpv3-'+uuid.uuid4().hex[:10]
        try:
            run(args.runtime, 'run', '-d', '--name', name, '--privileged', '-p', '127.0.0.1::1701/udp',
                '-e', 'LOCAL_COOKIE='+local, '-e', 'PEER_COOKIE='+peer, '-e', 'SUBLAYER='+layer,
                '-e', 'DYNAMIC='+str(int(dynamic)), '-e', 'SHARED_SECRET='+secret, 'localhost/yuhaiin-l2tpv3-test')
            ready(name, 'L2TPv3 server ready')
            # Server receive cookie == client transmit cookie, and vice versa.
            exercise('Linux L2TPv3 / '+label, {'L2TPV3_TEST_GATEWAY': gateway(name), 'L2TPV3_TEST_LOCAL_COOKIE': peer,
                     'L2TPV3_TEST_PEER_COOKIE': local, 'L2TPV3_TEST_SUBLAYER': layer,
                     'L2TPV3_TEST_DYNAMIC': str(int(dynamic)), 'L2TPV3_TEST_SECRET': secret}, '^TestLinuxL2TPv3', 'BenchmarkRealL2TPv3')
        except subprocess.CalledProcessError as exc:
            print(exc.stdout or '', exc.stderr or '', flush=True)
            subprocess.run([args.runtime, 'logs', name], check=False)
            raise
        finally:
            remove(name)

if args.output:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(host=platform.platform(), results=results), indent=2)+'\n')
