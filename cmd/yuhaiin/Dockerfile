FROM docker.io/library/golang:alpine AS builder

WORKDIR /yuhaiin

COPY . .

ENV GOTOOLCHAIN=auto

ARG EXTRA_GO_TAGS=""

RUN set -x\
    && apk add --no-cache make git\
    && make yuhaiin EXTRA_GO_TAGS="${EXTRA_GO_TAGS}"

FROM docker.io/library/alpine:latest

WORKDIR /yuhaiin

COPY --from=builder /yuhaiin/yuhaiin /yuhaiin/yuhaiin

ENTRYPOINT ["/yuhaiin/yuhaiin"]
