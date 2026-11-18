#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# End-to-end test of deploy/install.sh in a Debian 12 container: builds a
# linux binary for the Docker host's arch, packs it as a release archive with
# checksums.txt (plus a prerelease with a signature bundle and a release with a
# bad checksum), and runs
# install-e2e-inner.sh in the container against a real hub. Needs Docker and Go.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
image=${HEARTH_E2E_IMAGE:-debian:12}
version=0.0.0-e2e

case "$(docker info --format '{{.Architecture}}')" in
x86_64 | amd64) goarch=amd64 ;;
aarch64 | arm64) goarch=arm64 ;;
*)
  echo "install-e2e: unsupported Docker architecture" >&2
  exit 1
  ;;
esac

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d ' ' -f 1; else shasum -a 256 "$1" | cut -d ' ' -f 1; fi
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/build" "$work/srv/releases/v$version" "$work/srv/releases/v0.0.0-bad"

echo "install-e2e: building hearth for linux/$goarch"
CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -trimpath -ldflags "-s -w -X main.version=v$version" \
  -o "$work/build/hearth" ./cmd/hearth

asset=hearth_${version}_linux_${goarch}.tar.gz
tar_flags=()
if tar --version 2>/dev/null | grep -q bsdtar; then tar_flags=(--no-xattrs --no-mac-metadata); fi # no macOS metadata in the archive
COPYFILE_DISABLE=1 tar "${tar_flags[@]}" -czf "$work/srv/releases/v$version/$asset" -C "$work/build" hearth
printf '%s  %s\n' "$(sha256 "$work/srv/releases/v$version/$asset")" "$asset" >"$work/srv/releases/v$version/checksums.txt"
printf '{"tag_name": "v%s", "prerelease": false}\n' "$version" >"$work/srv/latest.json"

# A prerelease tag, as goreleaser names it: never "latest", only via --version.
rc=0.0.1-rc.1
mkdir -p "$work/srv/releases/v$rc"
cp "$work/srv/releases/v$version/$asset" "$work/srv/releases/v$rc/hearth_${rc}_linux_${goarch}.tar.gz"
sed "s/$asset/hearth_${rc}_linux_${goarch}.tar.gz/" "$work/srv/releases/v$version/checksums.txt" >"$work/srv/releases/v$rc/checksums.txt"
# Only this release has a signature bundle. Its content does not matter: the
# test puts a stub cosign on PATH, as a real Sigstore signature needs the
# release workflow's OIDC identity.
echo '{"stub": "sigstore bundle"}' >"$work/srv/releases/v$rc/checksums.txt.sigstore.json"
# GitHub's release list, newest first and pre-releases included, as the
# installer reads it when /releases/latest is 404 (no stable release yet).
printf '[\n  {\n    "tag_name": "v%s",\n    "prerelease": true\n  },\n  {\n    "tag_name": "v%s",\n    "prerelease": false\n  }\n]\n' \
  "$rc" "$version" >"$work/srv/releases.json"

bad=hearth_0.0.0-bad_linux_${goarch}.tar.gz
cp "$work/srv/releases/v$version/$asset" "$work/srv/releases/v0.0.0-bad/$bad"
printf '%064d  %s\n' 0 "$bad" >"$work/srv/releases/v0.0.0-bad/checksums.txt"

echo "install-e2e: running in $image"
# Copy files in rather than bind-mounting: works with remote Docker daemons
# and VMs (colima, Docker Desktop) that only share some host dirs.
# SYS_PTRACE lets the test's root read /proc/<pid>/environ of alice's
# processes, to check that the token does not leak into the installer's children.
cid=$(docker create --cap-add SYS_PTRACE -e "E2E_ASSETS=/srv/releases/v$version" "$image" bash /deploy/test/install-e2e-inner.sh)
trap 'docker rm -f "$cid" >/dev/null; rm -rf "$work"' EXIT
docker cp -q "$work/build/." "$cid:/build"
docker cp -q "$work/srv/." "$cid:/srv"
docker cp -q deploy/. "$cid:/deploy"
docker start -a "$cid"
