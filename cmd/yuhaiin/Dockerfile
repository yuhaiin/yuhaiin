FROM docker.io/library/golang:alpine AS builder

WORKDIR /yuhaiin

COPY . .

ENV GOTOOLCHAIN=auto

RUN set -x\
    && apk add --no-cache make git\
    && make yuhaiin

FROM docker.io/library/alpine:latest

WORKDIR /yuhaiin

COPY --from=builder /yuhaiin/yuhaiin /yuhaiin/yuhaiin

ENTRYPOINT ["/yuhaiin/yuhaiin"]
