import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 4242))
print("UDP echo ready", flush=True)
while True:
	packet, address = s.recvfrom(65535)
	s.sendto(packet, address)
