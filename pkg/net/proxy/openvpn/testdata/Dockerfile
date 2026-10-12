FROM docker.io/library/alpine:3.24
RUN apk add --no-cache openvpn openssl python3
COPY server.py /server.py
ENTRYPOINT ["python3", "/server.py"]
