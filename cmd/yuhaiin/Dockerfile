from docker.io/library/golang:alpine as builder

WORKDIR /yuhaiin

COPY . .

RUN set -x\
    && apk add --no-cache make git\
    && git config --global --add safe.directory '*'\
    && make yuhaiin

FROM docker.io/library/alpine:latest

WORKDIR /yuhaiin

COPY --from=builder /yuhaiin/yuhaiin /yuhaiin/yuhaiin

ENTRYPOINT ["/yuhaiin/yuhaiin"]
