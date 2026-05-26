FROM ccr.ccs.tencentyun.com/jxnxwy/ubuntu:22.04 AS runtime-local

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tshark tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && command -v tshark >/dev/null \
    && command -v mergecap >/dev/null

WORKDIR /app

COPY uepcap /usr/local/bin/uepcap

EXPOSE 8080
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/ >/dev/null || exit 1

CMD ["uepcap", "-port", "8080", "-data", "/app/data", "-ttl", "1h", "-max-jobs", "20"]

FROM node:20-bookworm AS frontend

WORKDIR /src

COPY web/package*.json ./web/
WORKDIR /src/web
RUN npm ci

COPY web/ /src/web/
RUN npm run build

FROM golang:1.24-bookworm AS backend

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=frontend /src/cmd/server/dist ./cmd/server/dist

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/uepcap ./cmd/server

FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tshark tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && command -v tshark >/dev/null \
    && command -v mergecap >/dev/null

WORKDIR /app

COPY --from=backend /out/uepcap /usr/local/bin/uepcap

EXPOSE 8080
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/ >/dev/null || exit 1

CMD ["uepcap", "-port", "8080", "-data", "/app/data", "-ttl", "1h", "-max-jobs", "20"]
