import socket
import threading

def tcp_client(c):
    with c:
        while True:
            data = c.recv(65535)
            if not data:
                return
            c.sendall(data)

def tcp_loop():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", 19991))
        s.listen(16)
        while True:
            c, _ = s.accept()
            threading.Thread(target=tcp_client, args=(c,), daemon=True).start()

def udp_loop():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", 19992))
        while True:
            data, addr = s.recvfrom(65535)
            s.sendto(data, addr)

threading.Thread(target=tcp_loop, daemon=True).start()
udp_loop()
