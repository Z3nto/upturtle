# syntax=docker/dockerfile:1

FROM golang:1.24.3 AS builder
WORKDIR /src
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o /out/upturtle ./cmd/upturtle

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       iputils-ping \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10001 appuser
WORKDIR /app
COPY --from=builder /out/upturtle /app/upturtle
# Create writable config directory for the non-root user
RUN mkdir -p /conf && chown -R 10001:10001 /conf
EXPOSE 8080
USER 10001
ENTRYPOINT ["/app/upturtle"]
