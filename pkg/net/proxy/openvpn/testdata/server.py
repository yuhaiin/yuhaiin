"""Disposable real OpenVPN server with independent TCP and UDP echo workers."""
import os
import pathlib
import socket
import subprocess
import threading

state = pathlib.Path('/state')
state.mkdir(exist_ok=True)
os.chdir(state)

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if not (state / 'ca.crt').exists():
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key',
        '-out', 'ca.crt', '-days', '2', '-subj', '/CN=Yuhaiin OpenVPN test CA')
    for role, usage in [('server', 'serverAuth'), ('client', 'clientAuth')]:
        run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', role+'.key',
            '-out', role+'.csr', '-subj', '/CN='+role)
        (state / 'extensions').write_text('keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\n')
        run('openssl', 'x509', '-req', '-in', role+'.csr', '-CA', 'ca.crt',
            '-CAkey', 'ca.key', '-CAcreateserial', '-days', '2', '-out', role+'.crt',
            '-extfile', 'extensions')
    run('openvpn', '--genkey', 'secret', 'ta.key')

network = os.environ.get('OVPN_NETWORK', 'udp')
cipher = os.environ.get('OVPN_CIPHER', 'AES-256-GCM')
protection = os.environ.get('OVPN_PROTECTION', 'tls-crypt')
config = '''port 1194
proto {proto}
dev tun
ca /state/ca.crt
cert /state/server.crt
key /state/server.key
dh none
server 10.88.0.0 255.255.255.0
server-ipv6 fd88::/64
topology subnet
data-ciphers {cipher}
keepalive 1 5
reneg-sec {reneg}
script-security 2
auth-user-pass-verify /state/auth.py via-file
verify-client-cert {verify}
remote-cert-tls client
push "dhcp-option DNS 10.88.0.1"
push "route 10.99.0.0 255.255.0.0"
verb 3
'''.format(proto='tcp-server' if network == 'tcp' else 'udp', cipher=cipher,
           reneg=os.environ.get('OVPN_RENEG', '3600'),
           verify='none' if os.environ.get('OVPN_NO_CERT') == '1' else 'require')
if protection == 'tls-crypt':
    config += 'tls-crypt /state/ta.key\n'
elif protection == 'tls-auth':
    config += 'tls-auth /state/ta.key 0\nauth SHA256\n'
(state / 'server.conf').write_text(config)
(state / 'auth.py').write_text('''#!/usr/bin/env python3
import pathlib, sys
credentials = pathlib.Path(sys.argv[1]).read_text().splitlines()
sys.exit(0 if credentials == ['alice', 'test-password'] else 1)
''')
(state / 'auth.py').chmod(0o700)

def tcp_echo():
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('::', 19991))
    listener.listen()
    def echo(conn):
        with conn:
            while data := conn.recv(65536):
                conn.sendall(data)
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=echo, args=(conn,), daemon=True).start()

def udp_echo():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind(('::', 19992))
    while True:
        data, addr = sock.recvfrom(65535)
        sock.sendto(data, addr)

threading.Thread(target=tcp_echo, daemon=True).start()
threading.Thread(target=udp_echo, daemon=True).start()
subprocess.run(['openvpn', '--config', str(state / 'server.conf')], check=True)
