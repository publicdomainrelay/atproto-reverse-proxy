# docker build --pull --push --progress plain -f client.Dockerfile -t atcr.io/johnandersen777.bsky.social/fedproxy-client .
#
# https://rp.fedproxy.com/v1/atproto/oauth/login?identifier=johnandersen777.bsky.social
#
# Run (oidc plugin — HANDLE and DID_PLC derived from accept.json):
#   docker run --rm \
#     --net host \
#     -e SERVICE=cfb3c8d2 \
#     -e PORT=8080 \
#     -e ATPRP_URL=https://rp.fedproxy.com \
#     -e AUTH_PLUGIN=oidc \
#     -e MARKET_ACCEPT_JSON_PATH=/root/secrets/publicdomainrelay.com/market/accept.json \
#     -v /root/secrets:/root/secrets:ro \
#     --entrypoint sudo \
#     atcr.io/johnandersen777.bsky.social/fedproxy-client \
#     -E fedproxy-client 2>&1 | jq --unbuffered .
#
# Run (oidc plugin — explicit HANDLE/DID_PLC):
#   docker run --rm \
#     -e ATPRP_URL=https://rp.fedproxy.com \
#     -e HANDLE=johnandersen777.bsky.social \
#     -e DID_PLC=did:plc:5svqtrhheairglgiiyvutzik \
#     -e AUTH_PLUGIN=oidc \
#     -e MARKET_ACCEPT_JSON_PATH=/run/secrets/accept.json \
#     -v /root/secrets:/run/secrets:ro \
#     atcr.io/johnandersen777.bsky.social/fedproxy-client
#
# Run (app-password plugin):
#   docker run --rm \
#     -e ATPRP_URL=https://rp.fedproxy.com \
#     -e MARKET_ACCEPT_JSON_PATH=/run/secrets/accept.json \
#     -e AUTH_PLUGIN=app-password \
#     -e ATPROTO_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx \
#     -v /root/secrets:/run/secrets:ro \
#     atcr.io/johnandersen777.bsky.social/fedproxy-client
#
# Optional env vars (both plugins):
#   SERVICE      – subdomain name (random hex if unset)
#   SSH_HOST     – SSH server host   (default: fedproxy.com)
#   SSH_PORT     – SSH server port   (default: 2222)
#   SSH_KEY_PATH – ed25519 key path  (default: ~/.ssh/id_ed25519)
#   LOCAL_ADDR   – local forward target (default: 127.0.0.1:8080)

# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /build

# Download dependencies (cached layer)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . /src

# Build static binary
RUN cd /src && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /build/fedproxy-client ./cmd/fedproxy-client

# Runtime stage
FROM debian:bookworm-slim

# Install sudo
RUN set -x \
  && apt-get update \
  && apt-get install -y \
       ca-certificates \
       jq \
       curl \
       git \
       sudo \
  && rm -rf /var/lib/apt/lists/*

# Create agent user
RUN useradd -m -s /bin/bash agent

# Setup passwordless sudo
RUN echo "agent ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/agent && \
    chmod 0440 /etc/sudoers.d/agent

# Copy binary from builder
COPY --from=builder /build/fedproxy-client /usr/local/bin/fedproxy-client

# Set working directory
WORKDIR /home/agent

# Switch to agent user
USER agent

# Default command
ENTRYPOINT ["fedproxy-client"]
