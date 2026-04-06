FROM docker.io/library/golang:1.26-alpine3.23 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o anytunnel .

FROM docker.io/library/alpine:3.23

COPY --from=builder /app/anytunnel /usr/local/bin/anytunnel

CMD ["anytunnel"]
