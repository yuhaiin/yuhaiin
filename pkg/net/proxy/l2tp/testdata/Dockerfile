FROM docker.io/library/alpine:3.22
RUN apk add --no-cache iproute2 python3
COPY v3-server.py /server.py
CMD ["python3", "/server.py"]
