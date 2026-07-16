FROM docker.io/library/alpine:latest

WORKDIR /yuhaiin

ARG TARGETARCH
ARG BINARY_SUFFIX=""

COPY --chmod=755 .docker-binaries/yuhaiin-linux-${TARGETARCH}${BINARY_SUFFIX} /yuhaiin/yuhaiin

ENTRYPOINT ["/yuhaiin/yuhaiin"]
