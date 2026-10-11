import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 4242))
print("UDP echo ready", flush=True)
while True:
    packet, peer = sock.recvfrom(65535)
    sock.sendto(packet, peer)
