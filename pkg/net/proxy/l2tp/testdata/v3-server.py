"""Linux L2TPv3 Ethernet peer with a UDP relay for rootless container NAT."""
import os
import hashlib
import hmac
import socket
import struct
import subprocess
import threading


def command(*args):
    subprocess.run(args, check=True)


local_cookie = os.environ.get("LOCAL_COOKIE", "")
peer_cookie = os.environ.get("PEER_COOKIE", "")
sublayer = os.environ.get("SUBLAYER", "none")
dynamic = os.environ.get("DYNAMIC", "0") == "1"
secret = os.environ.get("SHARED_SECRET", "").encode()
command("ip", "l2tp", "add", "tunnel", "tunnel_id", "200", "peer_tunnel_id", "100",
        "encap", "udp", "local", "127.0.0.1", "remote", "127.0.0.1",
        "udp_sport", "1702", "udp_dport", "1703")


def create_session(peer_id, outgoing_cookie, incoming_cookie, layer):
    args = ["ip", "l2tp", "add", "session", "tunnel_id", "200", "session_id", "200",
            "peer_session_id", str(peer_id), "l2spec_type", layer]
    # Linux's "cookie" is transmitted; "peer_cookie" is checked on receipt.
    if outgoing_cookie:
        args += ["cookie", outgoing_cookie]
    if incoming_cookie:
        args += ["peer_cookie", incoming_cookie]
    command(*args)
    command("ip", "link", "set", "l2tpeth0", "up")
    command("ip", "addr", "add", "10.89.0.1/24", "dev", "l2tpeth0")
    command("ip", "-6", "addr", "add", "fd89::1/64", "dev", "l2tpeth0")


if not dynamic:
    create_session(100, peer_cookie, local_cookie, sublayer)

front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
front.bind(("0.0.0.0", 1701))
back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
back.bind(("127.0.0.1", 1703))
peer = None


def avp(kind, data):
    return struct.pack("!HHH", 0x8000 | (6 + len(data)), 0, kind) + data


def short(value):
    return struct.pack("!H", value)


def long(value):
    return struct.pack("!I", value)


class Control:
    """Independent RFC 3931 signalling fixture; Linux owns the Ethernet wire."""
    def __init__(self):
        self.client_id = 0
        self.session_id = 0
        self.ns = self.nr = 0
        self.nonce = os.urandom(32)
        self.client_nonce = b""
        self.last_reply = None

    def digest(self, data, nonces):
        key = hmac.new(secret, b"\x02", hashlib.md5).digest()
        return hmac.new(key, nonces + data, hashlib.md5).digest()

    def send(self, kind, attrs=()):
        body = avp(0, short(kind))
        if secret:
            body += avp(59, b"\0" * 17)
        body += b"".join(avp(k, v) for k, v in attrs)
        data = struct.pack("!HHIHH", 0xc803, 12 + len(body), self.client_id, self.ns, self.nr) + body
        if secret:
            digest = self.digest(data, self.nonce + self.client_nonce)
            data = data[:27] + digest + data[43:]
        front.sendto(data, peer)
        self.last_reply = data
        if kind != 20:
            self.ns += 1

    def receive(self, data):
        if len(data) < 20:
            return
        flags, length, ccid, ns, nr = struct.unpack("!HHIHH", data[:12])
        if flags != 0xc803 or length != len(data):
            return
        attrs = {}
        offset = 12
        while offset < len(data):
            if offset + 6 > len(data):
                return
            flags, vendor, kind = struct.unpack("!HHH", data[offset:offset+6])
            size = flags & 1023
            if size < 6 or offset + size > len(data) or vendor != 0:
                return
            attrs[kind] = data[offset+6:offset+size]
            offset += size
        kind = struct.unpack("!H", attrs.get(0, b"\0\0"))[0]
        if kind == 1:
            self.client_nonce = attrs.get(73, b"")
        if secret:
            actual = attrs.get(59, b"")[1:]
            zeroed = data[:27] + b"\0" * 16 + data[43:]
            prefix = b"" if kind == 1 else self.client_nonce + self.nonce
            if len(actual) != 16 or not hmac.compare_digest(actual, self.digest(zeroed, prefix)):
                return
        if kind == 20:
            return
        if ns < self.nr:
            if self.last_reply:
                front.sendto(self.last_reply, peer)
            return
        if ns != self.nr:
            return
        self.nr += 1
        if kind == 1:
            required = (7, 60, 61, 62)
            if any(k not in attrs for k in required):
                raise RuntimeError("missing mandatory SCCRQ attribute")
            self.client_id = struct.unpack("!I", attrs[61])[0]
            reply = [(7, b"linux-test-peer"), (60, long(200)), (61, long(200)), (62, short(5))]
            if secret:
                reply.append((73, self.nonce))
            self.send(2, reply)
        elif kind == 4:
            self.send(20)
            if self.session_id:
                command("ip", "l2tp", "del", "session", "tunnel_id", "200", "session_id", "200")
            self.__init__()
        elif kind == 10:
            required = (63, 64, 15, 68, 66, 71)
            if any(k not in attrs for k in required) or attrs[68] != short(5):
                raise RuntimeError("invalid Ethernet ICRQ")
            self.session_id = struct.unpack("!I", attrs[63])[0]
            layer = "default" if attrs.get(69, short(0)) == short(1) else "none"
            cookie = bytes.fromhex(local_cookie)
            create_session(self.session_id, attrs.get(65, b"").hex(), local_cookie, layer)
            self.send(11, [(63, long(200)), (64, long(self.session_id)), (71, short(3)),
                           (65, cookie), (69, short(1 if layer == "default" else 0))])
        else:
            self.send(20)


control = Control()


def relay_back():
    while True:
        data, _ = back.recvfrom(65535)
        if peer:
            front.sendto(data, peer)


def tcp_client(conn):
    with conn:
        while data := conn.recv(65535):
            conn.sendall(data)


def echo_tcp(family):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", 19991))
        sock.listen()
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=tcp_client, args=(conn,), daemon=True).start()


def echo_udp(family):
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", 19992))
        while True:
            data, addr = sock.recvfrom(65535)
            sock.sendto(data, addr)


threading.Thread(target=relay_back, daemon=True).start()
for family in (socket.AF_INET, socket.AF_INET6):
    threading.Thread(target=echo_tcp, args=(family,), daemon=True).start()
    threading.Thread(target=echo_udp, args=(family,), daemon=True).start()
print("L2TPv3 server ready", flush=True)
while True:
    data, addr = front.recvfrom(65535)
    peer = addr
    if dynamic and len(data) >= 2 and data[0] & 0x80:
        control.receive(data)
        continue
    back.sendto(data, ("127.0.0.1", 1702))
