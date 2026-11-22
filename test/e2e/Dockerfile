# Hearth image for the end-to-end tests, built from the current checkout
# (context: the repository root). Not the release image; see /Dockerfile.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/hearth ./cmd/hearth

# A fresh device for autohub.compose.yaml: no hearth installed, curl to run
# the pasted install command, and /srv, a release server's files (the
# binary as a release archive, checksums.txt, latest.json) for install.sh.
FROM alpine:3.22 AS device
ARG TARGETARCH
RUN apk add --no-cache curl
COPY --from=build /out/hearth /build/hearth
RUN set -e; v=0.0.0-e2e; d=/srv/releases/v$v; a=hearth_${v}_linux_${TARGETARCH}.tar.gz; \
    mkdir -p "$d"; tar -czf "$d/$a" -C /build hearth; \
    (cd "$d" && sha256sum "$a" >checksums.txt); \
    printf '{"tag_name": "v%s"}\n' "$v" >/srv/latest.json; \
    rm /build/hearth

# alpine rather than distroless: the agent containers idle on `sleep` and the
# hub healthcheck needs `nc`.
FROM alpine:3.22
COPY --from=build /out/hearth /usr/bin/hearth
