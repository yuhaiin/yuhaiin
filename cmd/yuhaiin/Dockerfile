FROM docker.io/library/alpine:latest

WORKDIR /yuhaiin

ARG TARGETARCH
COPY --chmod=755 .docker-binaries/yuhaiin-linux-${TARGETARCH} /yuhaiin/yuhaiin

ENTRYPOINT ["/yuhaiin/yuhaiin"]
