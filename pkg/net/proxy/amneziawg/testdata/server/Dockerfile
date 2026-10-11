FROM golang:1.27-bookworm

RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		iproute2 wireguard-tools \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod ./go.mod
COPY go.sum ./go.sum
RUN go mod download
COPY main.go ./main.go
RUN go build -trimpath -o /usr/local/bin/awg-test-server .

EXPOSE 51820/udp
ENTRYPOINT ["/usr/local/bin/awg-test-server"]
