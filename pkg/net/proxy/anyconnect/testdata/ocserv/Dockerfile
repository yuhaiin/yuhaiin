FROM debian:bookworm-slim

RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		ocserv openssl python3 iproute2 iptables \
	&& rm -rf /var/lib/apt/lists/* \
	&& mkdir -p /etc/ocserv /run/ocserv \
	&& openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
		-keyout /etc/ocserv/server-key.pem -out /etc/ocserv/server-cert.pem \
		-subj '/CN=vpn.test' \
	&& printf 'test-password\ntest-password\n' | ocpasswd -c /etc/ocserv/ocpasswd alice

COPY ocserv.conf /etc/ocserv/ocserv.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 8443/tcp
ENTRYPOINT ["/entrypoint.sh"]
