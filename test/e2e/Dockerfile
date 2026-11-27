# Hearth image for the end-to-end tests, built from the current checkout
# (context: the repository root). Not the release image; see /Dockerfile.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Agents check a release's checksums.txt.sig before they upgrade (#359).
# This image's binaries are built with the e2etestkey tag, which trusts a
# test key linked in here instead of the release key, so the releases below
# can be signed here: its seed is 32 bytes of 0x01, a test value with no
# other use. A release build has no such tag, and no variable to link it in.
ARG E2E_TEST_ONLY_RELEASE_PUBKEY=iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=
ENV E2E_TEST_ONLY_LDFLAGS="-X github.com/gvart/hearth/internal/release.e2eTestKey=${E2E_TEST_ONLY_RELEASE_PUBKEY}"
RUN CGO_ENABLED=0 go build -trimpath -tags e2etestkey -ldflags "-s -w $E2E_TEST_ONLY_LDFLAGS" -o /out/hearth ./cmd/hearth
# The same binary as a "newer" release, for the agent upgrade of
# e2e_test.go (#347): only the version linked in differs.
RUN CGO_ENABLED=0 go build -trimpath -tags e2etestkey -ldflags "-s -w $E2E_TEST_ONLY_LDFLAGS -X main.version=v0.0.2-e2e" -o /out/hearth-next ./cmd/hearth
RUN CGO_ENABLED=0 go build -trimpath -tags e2etestkey -ldflags "-s -w $E2E_TEST_ONLY_LDFLAGS" -o /out/sign ./internal/release/cmd/sign

# A fresh device for autohub.compose.yaml: no hearth installed, curl to run
# the pasted install command, and /srv, a release server's files (the
# binary as a release archive, checksums.txt, latest.json) for install.sh,
# and the "newer" release v0.0.2-e2e agents upgrade to in e2e_test.go.
FROM alpine:3.22 AS device
RUN apk add --no-cache curl busybox-extras
COPY --from=build /out/hearth /build/hearth
COPY --from=build /out/hearth-next /build/next/hearth
COPY --from=build /out/sign /build/sign
# The arch from uname: the classic builder sets no TARGETARCH.
RUN set -e; case "$(uname -m)" in aarch64) arch=arm64 ;; x86_64) arch=amd64 ;; *) exit 1 ;; esac; \
    v=0.0.0-e2e; d=/srv/releases/v$v; a=hearth_${v}_linux_${arch}.tar.gz; \
    mkdir -p "$d"; tar -czf "$d/$a" -C /build hearth; \
    (cd "$d" && sha256sum "$a" >checksums.txt); \
    printf '{"tag_name": "v%s"}\n' "$v" >/srv/latest.json; \
    v=0.0.2-e2e; d=/srv/releases/v$v; a=hearth_${v}_linux_${arch}.tar.gz; \
    mkdir -p "$d"; tar -czf "$d/$a" -C /build/next hearth; \
    (cd "$d" && sha256sum "$a" >checksums.txt); \
    HEARTH_RELEASE_SIGNING_KEY=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE= /build/sign "$d/checksums.txt"; \
    rm -r /build

# alpine rather than distroless: the agent containers idle on `sleep` and the
# hub healthcheck needs `nc`.
FROM alpine:3.22
COPY --from=build /out/hearth /usr/bin/hearth
# A journalctl stand-in for the logs step (capabilities_test.go): alpine has no
# systemd. It prints one entry in journalctl's export format, then follows.
RUN printf '#!/bin/sh\nprintf "__REALTIME_TIMESTAMP=1700000000000000\\nMESSAGE=hearth e2e log line\\n\\n"\nexec sleep 3600\n' >/usr/bin/journalctl && \
    chmod 0755 /usr/bin/journalctl
# A systemctl stand-in for the local rule step (localrules_test.go): it
# records what it was asked to do.
RUN printf '#!/bin/sh\necho "$@" >>/tmp/hearth-e2e-restarts\n' >/usr/bin/systemctl && \
    chmod 0755 /usr/bin/systemctl
