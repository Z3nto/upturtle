# syntax=docker/dockerfile:1

FROM golang:1.24.3 AS builder
WORKDIR /src

RUN apt-get update && apt-get install -y gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .

ARG TARGETARCH
RUN CGO_ENABLED=1 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "-s -w" -o /out/upturtle ./cmd/upturtle

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       iputils-ping \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10001 appuser
WORKDIR /app
COPY --from=builder /out/upturtle /app/upturtle
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# Create writable directories for the non-root user
RUN mkdir -p /data/conf /data/db \
    && chown -R 10001:10001 /data \
    && chmod +x /usr/local/bin/docker-entrypoint.sh
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
