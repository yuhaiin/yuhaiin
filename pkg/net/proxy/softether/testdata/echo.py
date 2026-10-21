import os
import socket
import threading

# The CI-only option prints byte counts, never echoed application contents.
diagnostics = os.getenv("YUHAIIN_ECHO_DIAGNOSTICS") == "1"

def tcp_client(c):
    received = 0
    echoed = 0
    try:
        with c:
            while True:
                data = c.recv(65535)
                if not data:
                    return
                received += len(data)
                if diagnostics:
                    print(f"tcp-echo received={received} echoed={echoed}", flush=True)
                c.sendall(data)
                echoed += len(data)
                if diagnostics:
                    print(f"tcp-echo sent={echoed}", flush=True)
    finally:
        if diagnostics:
            print(f"tcp-echo finished received={received} echoed={echoed}", flush=True)

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
