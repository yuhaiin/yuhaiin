FROM ghcr.io/yuhaiin/yuhaiin:main

RUN apk add --no-cache openvpn curl supervisor

COPY supervisord.conf /etc/supervisord.conf

WORKDIR /app

ENTRYPOINT ["supervisord", "-n", "-c", "/etc/supervisord.conf"]
