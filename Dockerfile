FROM golang:1.19.3-alpine3.16 AS builder

WORKDIR /go/src

COPY ./go.mod ./go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o ./bin/auth-service ./cmd/

FROM alpine:3.16.3

WORKDIR /app

COPY ./docs/ ./docs/
COPY --from=builder /go/src/bin/auth-service .

ENTRYPOINT ["./auth-service"]
