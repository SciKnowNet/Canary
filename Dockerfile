FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o canary .

FROM alpine:latest
COPY --from=builder /app/canary /usr/local/bin/canary
ENTRYPOINT ["canary"]