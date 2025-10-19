FROM docker.io/library/golang:alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && apk add make

COPY . .

RUN make yuubinsya-http2

FROM docker.io/library/alpine:latest

WORKDIR /app

COPY --from=builder /app/yuubinsya ./

CMD ["./yuubinsya"]

EXPOSE 50051
