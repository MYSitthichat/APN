# Multi-stage static Go build for APN Self-Hosted Rendezvous Directory Server (~12 MB image!)
FROM golang:alpine AS builder
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/apn ./cmd/relayvpn

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /out/apn /usr/local/bin/apn
VOLUME ["/data"]
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/apn", "rdv-server", "-listen", "0.0.0.0:8787", "-snapshot", "/data/rdv-snapshot.json", "-ttl", "5m"]
