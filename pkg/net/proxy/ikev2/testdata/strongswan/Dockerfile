FROM debian:bookworm-slim

RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		strongswan strongswan-swanctl libcharon-extauth-plugins \
		libstrongswan-standard-plugins iproute2 iptables \
	&& rm -rf /var/lib/apt/lists/*

COPY swanctl.conf /etc/swanctl/swanctl.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 500/udp 4500/udp
ENTRYPOINT ["/entrypoint.sh"]
