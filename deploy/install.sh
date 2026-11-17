#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Hearth agent installer: downloads the hearth binary, verifies its SHA-256
# (and, when cosign is installed, the release's Sigstore signature), installs
# it to /usr/local/bin, enrolls this device with a hub and runs the agent as a
# service (systemd on Linux, launchd on macOS).
#
#   curl -fsSL http://<hub>:7080/install.sh | HEARTH_TOKEN=<token> sh -s -- --hub https://<hub>:7443
#
# The enrollment token comes in through the environment, which only the owner
# and root can read, not the argv, which any local user can see with ps.
# --token still works but warns for that reason.
#
# Re-running upgrades the binary and keeps the device identity (no token
# needed). --uninstall removes the service and binary; --purge also deletes the
# agent's data dir.
#
# Test-only environment overrides (not a supported interface):
#   HEARTH_INSTALL_PREFIX    install under this root instead of / (no root needed)
#   HEARTH_RELEASE_BASE_URL  base of <tag>/<asset> download URLs
#                            (default https://github.com/gvart/hearth/releases/download)
#   HEARTH_LATEST_URL        JSON with "tag_name" naming the latest release
#                            (default: the GitHub releases API)
#   HEARTH_SKIP_SERVICE=1    write the service file but do not call systemctl/launchctl
set -eu
# Never trace, even under `sh -x`: variables and arguments hold the enrollment token.
set +x

REPO=gvart/hearth
HUB_HTTP_PORT=7080
# Only the release workflow of gvart/Hearth, run for a v* tag, signs releases.
COSIGN_IDENTITY_REGEXP='^https://github\.com/gvart/Hearth/\.github/workflows/release\.yml@refs/tags/v'
COSIGN_OIDC_ISSUER=https://token.actions.githubusercontent.com
COSIGN_INSTALL_URL=https://docs.sigstore.dev/cosign/system_config/installation/
LAUNCHD_LABEL=dev.hearth.agent

PREFIX=${HEARTH_INSTALL_PREFIX:-}
RELEASE_BASE_URL=${HEARTH_RELEASE_BASE_URL:-https://github.com/$REPO/releases/download}
LATEST_URL=${HEARTH_LATEST_URL:-https://api.github.com/repos/$REPO/releases/latest}
SKIP_SERVICE=${HEARTH_SKIP_SERVICE:-0}

BIN_PATH=$PREFIX/usr/local/bin/hearth
DATA_DIR=$PREFIX/var/lib/hearth/agent
UNIT_PATH=$PREFIX/etc/systemd/system/hearth-agent.service
PLIST_PATH=$PREFIX/Library/LaunchDaemons/$LAUNCHD_LABEL.plist

say() { printf 'hearth: %s\n' "$*"; }
warn() { printf 'hearth: warning: %s\n' "$*" >&2; }
die() {
	printf 'hearth: error: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat <<'EOF'
Install the Hearth agent and enroll this device with a hub.

Usage:
  HEARTH_TOKEN=<token> install.sh --hub https://<hub>:7443   install and enroll
  install.sh [--version vX.Y.Z]                              upgrade an enrolled agent
  install.sh --uninstall [--purge]                           remove the agent

Environment:
  HEARTH_TOKEN       enrollment token from the hub (first install only)

Options:
  --hub URL          hub URL for enrollment (https://<hub>:7443)
  --token TOKEN      the enrollment token as an argument; avoid it: other local
                     users can read it with ps. Overrides HEARTH_TOKEN.
  --from-hub         download the binary from the hub (http://<hub>:7080/download/)
                     instead of GitHub releases
  --version vX.Y.Z   release to install (default: the latest release)
  --uninstall        stop and remove the service and binary; keep the data dir
  --purge            with --uninstall: also delete the data dir (device identity)
  -h, --help         show this help
EOF
}

HUB=
TOKEN=
FROM_HUB=0
VERSION=
UNINSTALL=0
PURGE=0

need_arg() {
	[ "$2" -ge 2 ] || die "$1 needs a value (see --help)"
}

while [ $# -gt 0 ]; do
	case $1 in
	--hub)
		need_arg "$1" $#
		HUB=$2
		shift 2
		;;
	--hub=*)
		HUB=${1#*=}
		shift
		;;
	--token)
		need_arg "$1" $#
		TOKEN=$2
		shift 2
		;;
	--token=*)
		TOKEN=${1#*=}
		shift
		;;
	--version)
		need_arg "$1" $#
		VERSION=$2
		shift 2
		;;
	--version=*)
		VERSION=${1#*=}
		shift
		;;
	--from-hub)
		FROM_HUB=1
		shift
		;;
	--uninstall)
		UNINSTALL=1
		shift
		;;
	--purge)
		UNINSTALL=1
		PURGE=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		# Do not echo the argument: it may be a mistyped token.
		die "unknown argument (see --help)"
		;;
	esac
done

# Take the token from the environment unless --token gave one, then drop
# HEARTH_TOKEN so no child process (curl, tar, sudo, ...) inherits it. TOKEN
# itself is never exported; join reads it on stdin.
if [ -n "$TOKEN" ]; then
	warn "--token exposes the token to other local users (ps); pass it as HEARTH_TOKEN=<token> instead"
	[ -z "${HEARTH_TOKEN:-}" ] || warn "both --token and HEARTH_TOKEN are set; using --token"
else
	TOKEN=${HEARTH_TOKEN:-}
fi
unset HEARTH_TOKEN

detect_platform() {
	case $(uname -s) in
	Linux) OS=linux ;;
	Darwin) OS=darwin ;;
	*) die "unsupported operating system: $(uname -s) (Hearth supports Linux and macOS)" ;;
	esac
	m=$(uname -m)
	case $m in
	x86_64 | amd64) ARCH=amd64 ;;
	aarch64 | arm64) ARCH=arm64 ;;
	armv7l | armv7) ARCH=armv7 ;;
	*) die "unsupported architecture: $m (Hearth supports amd64, arm64 and, on Linux, armv7)" ;;
	esac
	if [ "$OS" = darwin ] && [ "$ARCH" = armv7 ]; then
		die "unsupported platform: darwin/armv7"
	fi
}

# Privileged steps run as root: directly when we are root (or installing under
# a test prefix), through sudo otherwise.
setup_root() {
	SUDO=
	if [ -n "$PREFIX" ] || [ "$(id -u)" -eq 0 ]; then
		return
	fi
	if command -v sudo >/dev/null 2>&1; then
		say "not running as root; using sudo for the install steps"
		SUDO=sudo
		# Ask for the password now, on the terminal: later sudo calls read the
		# token from a pipe and must not prompt.
		sudo -v || die "sudo failed; re-run this installer as root"
		return
	fi
	die "this installer needs root: re-run it as root (sudo is not installed)"
}

as_root() {
	if [ -n "$SUDO" ]; then
		"$SUDO" "$@"
	else
		"$@"
	fi
}

# fetch URL DEST downloads URL to DEST with curl, or wget if curl is missing.
fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 -o "$2" "$1"
	else
		wget -q -O "$2" "$1"
	fi
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d ' ' -f 1
	else
		shasum -a 256 "$1" | cut -d ' ' -f 1
	fi
}

check_tools() {
	if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
		die "curl or wget is required to download Hearth"
	fi
	if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
		die "sha256sum or shasum is required to verify the download"
	fi
	for t in tar mktemp; do
		command -v "$t" >/dev/null 2>&1 || die "$t is required"
	done
}

# hub_host prints the host part of $HUB (https://host:port/...).
hub_host() {
	hp=${HUB#https://}
	hp=${hp%%/*}
	case $hp in
	*\]) printf '%s\n' "$hp" ;;
	*) printf '%s\n' "${hp%:*}" ;;
	esac
}

resolve_version() {
	if [ -n "$VERSION" ]; then
		case $VERSION in
		v*) ;;
		*) VERSION=v$VERSION ;;
		esac
		return
	fi
	say "looking up the latest release"
	fetch "$LATEST_URL" "$TMP/latest.json" || die "could not look up the latest release at $LATEST_URL; pass --version vX.Y.Z"
	VERSION=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$TMP/latest.json" | head -n 1)
	[ -n "$VERSION" ] || die "could not find the latest release tag; pass --version vX.Y.Z"
}

# verify_signature BASE checks the keyless Sigstore signature of
# $TMP/checksums.txt against BASE/checksums.txt.sigstore.json when cosign is
# installed, so that the SHA-256 checks below rest on a file the release
# workflow signed. Without cosign it says so and leaves only the SHA-256 check.
verify_signature() {
	if ! command -v cosign >/dev/null 2>&1; then
		say "cosign is not installed: the release signature was not checked, only SHA-256 (install cosign v3+ to check it: $COSIGN_INSTALL_URL)"
		return
	fi
	if ! fetch "$1/checksums.txt.sigstore.json" "$TMP/checksums.txt.sigstore.json" 2>/dev/null; then
		# A hub serves whatever its --assets-dir holds, which may be no bundle.
		[ "$FROM_HUB" = 1 ] ||
			die "could not download $1/checksums.txt.sigstore.json, the signature of checksums.txt; nothing was installed"
		say "the hub has no checksums.txt.sigstore.json in its --assets-dir: the release signature was not checked, only SHA-256"
		return
	fi
	say "verifying the signature of checksums.txt with cosign"
	if ! out=$(cd "$TMP" && cosign verify-blob --bundle checksums.txt.sigstore.json \
		--certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
		--certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" checksums.txt 2>&1); then
		printf '%s\n' "$out" >&2
		die "the signature of checksums.txt does not verify (not signed by the gvart/Hearth release workflow, or cosign is older than v3); nothing was installed"
	fi
	say "signature OK: checksums.txt was signed by the gvart/Hearth release workflow"
}

# download fetches and verifies the release archive, leaving the binary at $TMP/hearth.
download() {
	suffix=_${OS}_${ARCH}.tar.gz
	if [ "$FROM_HUB" = 1 ]; then
		[ -n "$HUB" ] || die "--from-hub needs --hub to know where the hub is"
		base=http://$(hub_host):$HUB_HTTP_PORT/download
		say "downloading checksums from the hub at $base"
		fetch "$base/checksums.txt" "$TMP/checksums.txt" ||
			die "could not download $base/checksums.txt (is the hub started with --assets-dir?)"
		if [ -n "$VERSION" ]; then
			asset=hearth_${VERSION#v}$suffix
		else
			asset=$(awk -v s="$suffix" '{ n = $2; sub(/^\*/, "", n); if (substr(n, length(n) - length(s) + 1) == s) { print n; exit } }' "$TMP/checksums.txt")
			[ -n "$asset" ] || die "the hub has no hearth build for $OS/$ARCH"
		fi
	else
		resolve_version
		asset=hearth_${VERSION#v}$suffix
		base=$RELEASE_BASE_URL/$VERSION
		say "downloading checksums for $VERSION"
		fetch "$base/checksums.txt" "$TMP/checksums.txt" ||
			die "could not download $base/checksums.txt (does release $VERSION exist?)"
	fi

	verify_signature "$base"

	say "downloading $asset"
	fetch "$base/$asset" "$TMP/$asset" || die "could not download $base/$asset"

	want=$(awk -v f="$asset" '{ n = $2; sub(/^\*/, "", n); if (n == f) { print $1; exit } }' "$TMP/checksums.txt")
	[ -n "$want" ] || die "checksums.txt has no entry for $asset"
	got=$(sha256_of "$TMP/$asset")
	if [ "$got" != "$want" ]; then
		die "checksum mismatch for $asset (expected $want, got $got); nothing was installed"
	fi
	say "checksum OK"

	tar -xzf "$TMP/$asset" -C "$TMP" hearth || die "could not extract hearth from $asset"
	"$TMP/hearth" version >/dev/null 2>&1 || die "the downloaded binary does not run on this machine ($OS/$ARCH)"
}

install_binary() {
	as_root mkdir -p "${BIN_PATH%/*}"
	# Install next to the target and rename, so a running agent is not disturbed.
	as_root cp "$TMP/hearth" "$BIN_PATH.new"
	as_root chmod 0755 "$BIN_PATH.new"
	as_root mv -f "$BIN_PATH.new" "$BIN_PATH"
	say "installed $("$BIN_PATH" version | head -n 1) to $BIN_PATH"
}

write_systemd_unit() {
	cat >"$1" <<'HEARTH_SYSTEMD_UNIT'
# SPDX-License-Identifier: AGPL-3.0-only
# Installed by deploy/install.sh, which embeds a copy; keep the two identical.
[Unit]
Description=Hearth agent
Documentation=https://github.com/gvart/hearth
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hearth agent run --data-dir /var/lib/hearth/agent
Restart=always
RestartSec=5
UMask=0077
# Hardening that keeps host fact collection (/proc, /sys, mounts) working.
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
HEARTH_SYSTEMD_UNIT
}

write_launchd_plist() {
	cat >"$1" <<'HEARTH_LAUNCHD_PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Installed by deploy/install.sh, which embeds a copy; keep the two identical. -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>dev.hearth.agent</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/local/bin/hearth</string>
		<string>agent</string>
		<string>run</string>
		<string>--data-dir</string>
		<string>/var/lib/hearth/agent</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>5</integer>
	<key>Umask</key>
	<integer>63</integer>
	<key>StandardOutPath</key>
	<string>/var/log/hearth-agent.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/hearth-agent.log</string>
</dict>
</plist>
HEARTH_LAUNCHD_PLIST
}

skip_service() {
	[ "$SKIP_SERVICE" = 1 ]
}

install_service() {
	if [ "$OS" = linux ]; then
		write_systemd_unit "$TMP/hearth-agent.service"
		as_root mkdir -p "${UNIT_PATH%/*}"
		as_root cp "$TMP/hearth-agent.service" "$UNIT_PATH"
		as_root chmod 0644 "$UNIT_PATH"
		if skip_service; then
			say "wrote $UNIT_PATH (HEARTH_SKIP_SERVICE=1: not starting it)"
			return
		fi
		if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
			warn "systemd is not running here; start the agent yourself: $BIN_PATH agent run --data-dir $DATA_DIR"
			return
		fi
		as_root systemctl daemon-reload
		as_root systemctl enable hearth-agent.service >/dev/null 2>&1
		as_root systemctl restart hearth-agent.service
		say "service hearth-agent is running (logs: journalctl -u hearth-agent -f)"
	else
		write_launchd_plist "$TMP/$LAUNCHD_LABEL.plist"
		as_root mkdir -p "${PLIST_PATH%/*}"
		as_root cp "$TMP/$LAUNCHD_LABEL.plist" "$PLIST_PATH"
		as_root chmod 0644 "$PLIST_PATH"
		if skip_service; then
			say "wrote $PLIST_PATH (HEARTH_SKIP_SERVICE=1: not loading it)"
			return
		fi
		as_root launchctl bootout "system/$LAUNCHD_LABEL" >/dev/null 2>&1 || true
		as_root launchctl enable "system/$LAUNCHD_LABEL"
		as_root launchctl bootstrap system "$PLIST_PATH"
		say "service $LAUNCHD_LABEL is running (logs: /var/log/hearth-agent.log)"
	fi
}

remove_service() {
	if [ "$OS" = linux ]; then
		if ! skip_service && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
			as_root systemctl disable --now hearth-agent.service >/dev/null 2>&1 || true
		fi
		as_root rm -f "$UNIT_PATH"
		if ! skip_service && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
			as_root systemctl daemon-reload
		fi
	else
		if ! skip_service; then
			as_root launchctl bootout "system/$LAUNCHD_LABEL" >/dev/null 2>&1 || true
		fi
		as_root rm -f "$PLIST_PATH"
	fi
}

uninstall() {
	remove_service
	as_root rm -f "$BIN_PATH"
	say "removed the hearth service and $BIN_PATH"
	if [ "$PURGE" = 1 ]; then
		as_root rm -rf "$DATA_DIR"
		as_root rmdir "${DATA_DIR%/*}" >/dev/null 2>&1 || true
		say "deleted $DATA_DIR; the device stays listed on the hub until you remove it there"
	else
		say "kept $DATA_DIR (device identity); run with --purge to delete it"
	fi
}

enrolled() {
	as_root test -f "$DATA_DIR/agent.crt"
}

main() {
	detect_platform
	setup_root

	if [ "$UNINSTALL" = 1 ]; then
		uninstall
		return
	fi

	if enrolled; then
		say "this device is already enrolled ($DATA_DIR/agent.crt); upgrading and keeping its identity"
		[ -z "$TOKEN" ] || say "ignoring the enrollment token: a token is not needed for an upgrade"
		JOIN=0
	else
		[ -n "$HUB" ] || die "--hub is required for a first install (e.g. --hub https://<hub>:7443)"
		[ -n "$TOKEN" ] || die "an enrollment token is required for a first install: pass HEARTH_TOKEN=<token> (create one in the hub UI or with 'hearth token create')"
		case $HUB in
		https://*) ;;
		*) die "--hub must be an https:// URL (the hub's agent port, usually 7443)" ;;
		esac
		JOIN=1
	fi

	check_tools
	TMP=$(mktemp -d)
	trap 'rm -rf "$TMP"' EXIT
	trap 'exit 130' INT TERM

	download
	install_binary
	as_root mkdir -p "$DATA_DIR"
	as_root chmod 0700 "$DATA_DIR"

	if [ "$JOIN" = 1 ]; then
		say "enrolling with $HUB"
		# The token goes in on stdin (printf is a shell builtin), never in argv,
		# so neither ps nor sudo's log ever sees it.
		printf '%s\n' "$TOKEN" | as_root "$BIN_PATH" agent join --data-dir "$DATA_DIR" "$HUB" - ||
			die "enrollment failed (is the token valid and unused, and the hub reachable at $HUB?)"
	fi

	install_service
	say "done: this device should show up in the hub UI within seconds"
}

main
