# Build a static single binary (modernc sqlite is pure Go → CGO_ENABLED=0).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/proxymachine .

FROM alpine:3.20
RUN adduser -D -u 10001 app && mkdir -p /data && chown app /data
COPY --from=build /out/proxymachine /usr/local/bin/proxymachine
USER app
WORKDIR /data

# API, HTTP relay, SOCKS5 listener. NOTE: the binary binds LOOPBACK by default, so a bare
# `docker run` is safe but unreachable from outside the container. To expose it, override
# the addresses to 0.0.0.0 AND set --proxyUser/--proxyPass, e.g.:
#   docker run -p 3333:3333 -p 8000:8000 -p 1080:1080 -v pm:/data proxymachine \
#     --relayAddr 0.0.0.0:3333 --apiAddr 0.0.0.0:8000 --socksAddr 0.0.0.0:1080 \
#     --proxyUser u --proxyPass p
EXPOSE 8000 3333 1080

ENTRYPOINT ["proxymachine"]
CMD ["--dbPath", "/data/data.db"]
