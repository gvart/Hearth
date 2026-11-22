#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Hearth agent installer: downloads the hearth binary, verifies its SHA-256
# (and, when cosign is installed, the release's Sigstore signature), installs
# it to /usr/local/bin, enrolls this device with a hub and runs the agent as a
# service (systemd on Linux, launchd on macOS).
#
#   curl -fsSL https://raw.githubusercontent.com/gvart/Hearth/<tag>/deploy/install.sh |
#     HEARTH_TOKEN=<token> sh -s -- --version <tag>
#
# The hub's "Add device" dialog shows this command with the token filled in
# (a dev build of the hub serves the script itself, from
# http://<hub>:7080/install.sh). The token names the hub (its agent URL and CA
# fingerprint), so no flag does; --hub gives the hub URL for a token that
# names none, or one to use when this device cannot reach the hub the token
# names.
#
# The enrollment token comes in through the environment, which only the owner
# and root can read, not the argv, which any local user can see with ps.
# --token still works but warns for that reason.
#
# On Linux, a capable device (64-bit, 1.5 GiB of memory, 2 GiB free) enrolled
# with a token the admin made hub-eligible ("This device may become a hub" in
# Add device) also becomes a hub of the cluster: the enrollment writes a join
# into /var/lib/hearth/hub, and the hearth-hub service joins with it. Nothing
# to pass for that; --agent-only (or HEARTH_AGENT_ONLY=1) keeps the device an
# agent.
#
# An enrolled device, a Mac too, becomes a hub later from its page in the web
# UI ("Make this device a hub"): the page shows a re-run with --make-hub
# <master URL> and HEARTH_JOIN_TOKEN, which writes the join and installs the
# hub service (hearth-hub.service, or dev.hearth.hub on macOS) next to the
# agent. A re-run with --agent-only stops and removes that service.
#
# Re-running upgrades the binary and keeps the device identity (no token
# needed). --uninstall removes the services and binary; --purge also deletes
# the agent's and the hub's data dirs.
#
# Test-only environment overrides (not a supported interface):
#   HEARTH_INSTALL_PREFIX    install under this root instead of / (no root needed)
#   HEARTH_RELEASE_BASE_URL  base of <tag>/<asset> download URLs
#                            (default https://github.com/gvart/hearth/releases/download)
#   HEARTH_LATEST_URL        JSON with "tag_name" naming the latest release
#                            (default: the GitHub releases API)
#   HEARTH_RELEASES_URL      JSON whose first "tag_name" names the newest release,
#                            pre-releases included, used when HEARTH_LATEST_URL
#                            fails (default: the GitHub releases API)
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
LAUNCHD_HUB_LABEL=dev.hearth.hub

PREFIX=${HEARTH_INSTALL_PREFIX:-}
RELEASE_BASE_URL=${HEARTH_RELEASE_BASE_URL:-https://github.com/$REPO/releases/download}
LATEST_URL=${HEARTH_LATEST_URL:-https://api.github.com/repos/$REPO/releases/latest}
# GitHub lists releases newest first; /releases/latest skips pre-releases.
RELEASES_URL=${HEARTH_RELEASES_URL:-https://api.github.com/repos/$REPO/releases?per_page=1}
SKIP_SERVICE=${HEARTH_SKIP_SERVICE:-0}

BIN_PATH=$PREFIX/usr/local/bin/hearth
DATA_DIR=$PREFIX/var/lib/hearth/agent
HUB_DATA_DIR=$PREFIX/var/lib/hearth/hub
UNIT_PATH=$PREFIX/etc/systemd/system/hearth-agent.service
HUB_UNIT_PATH=$PREFIX/etc/systemd/system/hearth-hub.service
PLIST_PATH=$PREFIX/Library/LaunchDaemons/$LAUNCHD_LABEL.plist
HUB_PLIST_PATH=$PREFIX/Library/LaunchDaemons/$LAUNCHD_HUB_LABEL.plist

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
  HEARTH_TOKEN=<token> install.sh [--hub https://<hub>:7443]   install and enroll
  install.sh [--version vX.Y.Z]                                 upgrade an enrolled agent
  HEARTH_JOIN_TOKEN=<token> install.sh --make-hub https://<master>:7443
                                                                make this device a hub too
  install.sh --uninstall [--purge]                              remove the agent

Environment:
  HEARTH_TOKEN       enrollment token from the hub (first install only)
  HEARTH_AGENT_ONLY  1: as --agent-only
  HEARTH_JOIN_TOKEN  with --make-hub: the cluster join token from the device's page

Options:
  --hub URL          hub URL for enrollment (https://<hub>:7443); the token names
                     the hub, so it is needed only if the token names none, or
                     to reach the hub at another address
  --token TOKEN      the enrollment token as an argument; avoid it: other local
                     users can read it with ps. Overrides HEARTH_TOKEN.
  --from-hub         download the binary from the hub (http://<hub>:7080/download/)
                     instead of GitHub releases
  --version vX.Y.Z   release to install (default: the latest release, or the
                     newest pre-release while there is no stable one)
  --agent-only       never make this device a hub, even when it is capable and
                     the token allows it; on a hub, stop and remove its service
                     (its data dir is kept)
  --make-hub URL     make this device a hub of the cluster too, through the
                     master at URL (https://<master>:7443), with the join token
                     in HEARTH_JOIN_TOKEN: the device's page in the web UI shows
                     this command. A Mac qualifies; every device needs a 64-bit
                     CPU, 1.5 GiB of memory and 2 GiB free.
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
AGENT_ONLY=${HEARTH_AGENT_ONLY:-0}
MAKE_HUB=

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
	--agent-only)
		AGENT_ONLY=1
		shift
		;;
	--make-hub)
		need_arg "$1" $#
		MAKE_HUB=$2
		shift 2
		;;
	--make-hub=*)
		MAKE_HUB=${1#*=}
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
# The join token of --make-hub, likewise: never exported, given on stdin.
JOIN_TOKEN=${HEARTH_JOIN_TOKEN:-}
unset HEARTH_JOIN_TOKEN

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
	# GitHub answers 404 here while every release is a pre-release.
	if fetch "$LATEST_URL" "$TMP/latest.json" 2>/dev/null; then
		VERSION=$(tag_name "$TMP/latest.json")
	fi
	if [ -z "$VERSION" ]; then
		say "found no stable release; looking up the newest release, pre-releases included"
		fetch "$RELEASES_URL" "$TMP/latest.json" || die "could not look up the releases at $RELEASES_URL; pass --version vX.Y.Z"
		VERSION=$(tag_name "$TMP/latest.json")
		[ -n "$VERSION" ] || die "found no release at $RELEASES_URL; pass --version vX.Y.Z"
	fi
}

# tag_name FILE prints the first "tag_name" in the JSON in FILE.
tag_name() {
	sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -n 1
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
# 78: the device certificate was revoked; restarting cannot help, re-enroll.
RestartPreventExitStatus=78
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

write_hub_unit() {
	cat >"$1" <<'HEARTH_HUB_UNIT'
# SPDX-License-Identifier: AGPL-3.0-only
# Installed by deploy/install.sh, which embeds a copy; keep the two identical.
# The hub of a device the cluster made a hub at its enrollment (docs/cluster.md,
# "Devices become hubs"): it joins with the join file the enrollment wrote,
# never creating a cluster of its own, then runs as a member.
[Unit]
Description=Hearth hub
Documentation=https://github.com/gvart/hearth
After=network-online.target
Wants=network-online.target
# Only a device with a join to make, or one that joined already.
ConditionPathExists=|/var/lib/hearth/hub/join
ConditionPathExists=|/var/lib/hearth/hub/cluster/node.crt

[Service]
Type=simple
ExecStart=/usr/local/bin/hearth hub --data-dir /var/lib/hearth/hub --join-file /var/lib/hearth/hub/join
# A join refused for good, or no join to make, exits 0 and is not restarted;
# a join that may pass (the master unreachable) tries again until its token
# expires.
Restart=on-failure
RestartSec=10
UMask=0077
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
HEARTH_HUB_UNIT
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

write_launchd_hub_plist() {
	cat >"$1" <<'HEARTH_LAUNCHD_HUB_PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Installed by deploy/install.sh, which embeds a copy; keep the two identical. -->
<!-- The hub of a Mac made a hub on its page in the web UI (docs/cluster.md), as -->
<!-- deploy/systemd/hearth-hub.service on Linux: it joins with the join file, -->
<!-- never creating a cluster of its own, then runs as a member. A join refused -->
<!-- for good, or no join to make, exits 0 and is not restarted. -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>dev.hearth.hub</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/local/bin/hearth</string>
		<string>hub</string>
		<string>--data-dir</string>
		<string>/var/lib/hearth/hub</string>
		<string>--join-file</string>
		<string>/var/lib/hearth/hub/join</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>Umask</key>
	<integer>63</integer>
	<key>StandardOutPath</key>
	<string>/var/log/hearth-hub.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/hearth-hub.log</string>
</dict>
</plist>
HEARTH_LAUNCHD_HUB_PLIST
}

skip_service() {
	[ "$SKIP_SERVICE" = 1 ]
}

systemd_running() {
	command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
}

# is_hub reports whether this device has a hub to run: a join the enrollment
# wrote, or a hub that joined already; never with --agent-only.
is_hub() {
	[ "$AGENT_ONLY" != 1 ] &&
		{ as_root test -f "$HUB_DATA_DIR/join" || as_root test -f "$HUB_DATA_DIR/cluster/node.crt"; }
}

# hub_service_file is the hub's systemd unit or launchd plist.
hub_service_file() {
	if [ "$OS" = linux ]; then
		printf '%s\n' "$HUB_UNIT_PATH"
	else
		printf '%s\n' "$HUB_PLIST_PATH"
	fi
}

# remove_hub_service stops, disables and removes the hub's unit or plist, if
# there is one; it keeps the hub's data dir.
remove_hub_service() {
	as_root test -f "$(hub_service_file)" || return 0
	if [ "$OS" = darwin ]; then
		skip_service || as_root launchctl bootout "system/$LAUNCHD_HUB_LABEL" >/dev/null 2>&1 || true
		as_root rm -f "$HUB_PLIST_PATH"
		return
	fi
	if ! skip_service && systemd_running; then
		as_root systemctl disable --now hearth-hub.service >/dev/null 2>&1 || true
	fi
	as_root rm -f "$HUB_UNIT_PATH"
	if ! skip_service && systemd_running; then
		as_root systemctl daemon-reload
	fi
}

# install_hub_service installs and starts the hub before the agent, and waits
# up to 60 s for it to answer `hearth cluster status` (a member that is no
# master serves no web port). A hub that fails leaves a working agent.
install_hub_service() {
	if [ "$OS" = darwin ]; then
		write_launchd_hub_plist "$TMP/$LAUNCHD_HUB_LABEL.plist"
		as_root mkdir -p "${HUB_PLIST_PATH%/*}"
		as_root cp "$TMP/$LAUNCHD_HUB_LABEL.plist" "$HUB_PLIST_PATH"
		as_root chmod 0644 "$HUB_PLIST_PATH"
		if skip_service; then
			say "wrote $HUB_PLIST_PATH (HEARTH_SKIP_SERVICE=1: not loading it)"
			return
		fi
		as_root launchctl bootout "system/$LAUNCHD_HUB_LABEL" >/dev/null 2>&1 || true
		as_root launchctl enable "system/$LAUNCHD_HUB_LABEL"
		as_root launchctl bootstrap system "$HUB_PLIST_PATH"
		hub_logs=/var/log/hearth-hub.log
	else
		write_hub_unit "$TMP/hearth-hub.service"
		as_root mkdir -p "${HUB_UNIT_PATH%/*}"
		as_root cp "$TMP/hearth-hub.service" "$HUB_UNIT_PATH"
		as_root chmod 0644 "$HUB_UNIT_PATH"
		if skip_service; then
			say "wrote $HUB_UNIT_PATH (HEARTH_SKIP_SERVICE=1: not starting it)"
			return
		fi
		if ! systemd_running; then
			warn "systemd is not running here; start the hub yourself: $BIN_PATH hub --data-dir $HUB_DATA_DIR --join-file $HUB_DATA_DIR/join"
			return
		fi
		as_root systemctl daemon-reload
		as_root systemctl enable hearth-hub.service >/dev/null 2>&1
		as_root systemctl restart hearth-hub.service
		hub_logs="journalctl -u hearth-hub -f"
	fi
	say "starting the hub: this device joins the cluster as a hub"
	i=0
	while [ $i -lt 60 ]; do
		if as_root "$BIN_PATH" cluster status --data-dir "$HUB_DATA_DIR" >/dev/null 2>&1; then
			say "the hub is running (logs: $hub_logs)"
			return
		fi
		i=$((i + 1))
		sleep 1
	done
	warn "the hub did not answer within 60 s; the agent runs anyway (logs: $hub_logs)"
}

install_service() {
	if is_hub; then
		install_hub_service
	elif [ "$AGENT_ONLY" = 1 ] && as_root test -f "$(hub_service_file)"; then
		remove_hub_service
		say "--agent-only: stopped and removed the hub service (kept $HUB_DATA_DIR; --purge deletes it)"
	fi
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
		remove_hub_service
		if ! skip_service && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
			as_root systemctl disable --now hearth-agent.service >/dev/null 2>&1 || true
		fi
		as_root rm -f "$UNIT_PATH"
		if ! skip_service && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
			as_root systemctl daemon-reload
		fi
	else
		remove_hub_service
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
		as_root rm -rf "$DATA_DIR" "$HUB_DATA_DIR"
		as_root rmdir "${DATA_DIR%/*}" >/dev/null 2>&1 || true
		say "deleted $DATA_DIR and $HUB_DATA_DIR; the device (and its hub) stay listed until you remove them there"
	else
		say "kept $DATA_DIR (device identity) and any $HUB_DATA_DIR; run with --purge to delete them"
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

	if [ -n "$MAKE_HUB" ]; then
		case $MAKE_HUB in
		https://*) ;;
		*) die "--make-hub must be an https:// URL (the master's agent port, usually 7443)" ;;
		esac
		[ "$AGENT_ONLY" != 1 ] || die "--make-hub and --agent-only contradict each other"
		[ -n "$JOIN_TOKEN" ] || die "--make-hub needs the join token in HEARTH_JOIN_TOKEN (the device's page in the web UI shows the command)"
	fi

	if enrolled; then
		say "this device is already enrolled ($DATA_DIR/agent.crt); upgrading and keeping its identity"
		[ -z "$TOKEN" ] || say "ignoring the enrollment token: a token is not needed for an upgrade"
		JOIN=0
	else
		[ -n "$TOKEN" ] || die "an enrollment token is required for a first install: pass HEARTH_TOKEN=<token> (create one in the hub UI or with 'hearth token create')"
		if [ -n "$HUB" ]; then
			case $HUB in
			https://*) ;;
			*) die "--hub must be an https:// URL (the hub's agent port, usually 7443)" ;;
			esac
		else
			# A hearth2 token names its hub (hearth2.<secret>.<fingerprint>.<url>);
			# hearth agent join reads and checks the URL.
			case $TOKEN in
			hearth2.*.*.*) ;;
			*) die "the token names no hub: pass --hub https://<hub>:7443" ;;
			esac
		fi
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
		# Offer this device as a hub: the agent checks it is capable, the hub
		# that the token allows it. Linux only; never with --agent-only.
		set --
		if [ "$OS" = linux ] && [ "$AGENT_ONLY" != 1 ]; then
			set -- --hub-data-dir "$HUB_DATA_DIR"
		fi
		# The token goes in on stdin (printf is a shell builtin), never in argv,
		# so neither ps nor sudo's log ever sees it.
		if [ -n "$HUB" ]; then
			say "enrolling with $HUB"
			printf '%s\n' "$TOKEN" | as_root "$BIN_PATH" agent join --data-dir "$DATA_DIR" "$@" "$HUB" - ||
				die "enrollment failed (is the token valid and unused, and the hub reachable at $HUB?)"
		else
			say "enrolling with the hub the token names"
			printf '%s\n' "$TOKEN" | as_root "$BIN_PATH" agent join --data-dir "$DATA_DIR" "$@" - ||
				die "enrollment failed (is the token valid and unused, and the hub it names reachable? --hub https://<hub>:7443 gives another address)"
		fi
	fi

	if [ -n "$MAKE_HUB" ]; then
		# The join token goes in on stdin, as the enrollment token does. A
		# device that cannot become a hub still gets its agent (re)started.
		printf '%s\n' "$JOIN_TOKEN" | as_root "$BIN_PATH" agent make-hub --hub-data-dir "$HUB_DATA_DIR" "$MAKE_HUB" - ||
			warn "this device stays an agent: it did not become a hub (see above)"
	fi

	install_service
	say "done: this device should show up in the hub UI within seconds"
}

main
