"""Stock xl2tpd/pppd peer for PAP, CHAP-MD5, MS-CHAPv2 and IPv6CP."""
import os
from pathlib import Path
import socket
import subprocess
import threading


def tcp_client(conn):
    with conn:
        while data := conn.recv(65535):
            conn.sendall(data)


def tcp(family):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', 19991))
        sock.listen()
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=tcp_client, args=(conn,), daemon=True).start()


def udp(family):
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', 19992))
        while True:
            data, peer = sock.recvfrom(65535)
            sock.sendto(data, peer)


Path('/etc/xl2tpd').mkdir(exist_ok=True)
Path('/etc/xl2tpd/xl2tpd.conf').write_text('''[global]
port = 1701
force userspace = yes
[lns default]
ip range = 10.88.0.2-10.88.0.32
local ip = 10.88.0.1
require authentication = yes
name = l2tp-test
pppoptfile = /etc/ppp/options.l2tp
length bit = yes
''')
auth = {'pap': 'require-pap', 'chap-md5': 'require-chap', 'mschap-v2': 'require-mschap-v2'}[os.environ.get('PPP_AUTH', 'pap')]
Path('/etc/ppp').mkdir(exist_ok=True)
Path('/etc/ppp/options.l2tp').write_text(f'''{auth}
name l2tp-test
noccp
noipdefault
nodefaultroute
mtu 1400
mru 1400
ms-dns 10.88.0.1
ipv6 ::1,::2
ipv6cp-accept-local
lcp-echo-interval 2
lcp-echo-failure 3
logfile /dev/stdout
''')
for name in ('pap-secrets', 'chap-secrets'):
    file = Path('/etc/ppp')/name
    file.write_text('alice * test-password *\n')
    file.chmod(0o600)
script = Path('/etc/ppp/ipv6-up')
script.write_text('#!/bin/sh\nip -6 addr add fd88::1/64 dev "$1"\n')
script.chmod(0o755)
for family in (socket.AF_INET, socket.AF_INET6):
    threading.Thread(target=tcp, args=(family,), daemon=True).start()
    threading.Thread(target=udp, args=(family,), daemon=True).start()
server = subprocess.Popen(['xl2tpd', '-D'])
# Leave the daemon a moment to bind its listening socket before tests start.
import time
time.sleep(.5)
if server.poll() is not None:
    raise RuntimeError('xl2tpd failed to start')
print('PPP server ready', flush=True)
raise SystemExit(server.wait())
