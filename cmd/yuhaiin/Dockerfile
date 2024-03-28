FROM docker.io/library/golang:alpine as builder

WORKDIR /yuhaiin

COPY . .

RUN set -x\
    && apk add --no-cache make git\
    && make yuhaiin

FROM docker.io/library/alpine:latest

WORKDIR /yuhaiin

COPY --from=builder /yuhaiin/yuhaiin /yuhaiin/yuhaiin

ENTRYPOINT ["/yuhaiin/yuhaiin"]
