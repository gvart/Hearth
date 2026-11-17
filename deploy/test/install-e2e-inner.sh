#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Runs inside the container started by install-e2e.sh. /build/hearth is the
# hub binary, /srv the fake release server, /deploy a copy of the repo's deploy dir.
set -euo pipefail

HUB=https://127.0.0.1:7443
WEB=http://127.0.0.1:7080
PASSWORD=e2e-admin-password
DATA=/var/lib/hearth/agent
UNIT=/etc/systemd/system/hearth-agent.service
export HEARTH_RELEASE_BASE_URL=http://127.0.0.1:8000/releases
export HEARTH_LATEST_URL=http://127.0.0.1:8000/latest.json
export HEARTH_SKIP_SERVICE=1 # no systemd in the container; the test runs ExecStart itself

ms() { date +%s%3N; }
log() { printf '\n=== %s\n' "$*"; }
fail() {
  printf 'FAIL: %s\n' "$*" >&2
  for f in /tmp/hub.log /tmp/agent.log; do [ -f "$f" ] && { echo "--- $f"; tail -n 30 "$f"; }; done
  exit 1
}
pass() { printf 'ok: %s\n' "$*"; }

wait_for() { # seconds, command...
  local deadline=$(($(date +%s) + $1))
  shift
  until "$@" >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 0.2
  done
}

# expect_fail NAME PATTERN command... runs command, which must fail and print PATTERN.
expect_fail() {
  local name=$1 pattern=$2 out
  shift 2
  if out=$("$@" 2>&1); then fail "$name: succeeded, want failure"; fi
  grep -q -- "$pattern" <<<"$out" || fail "$name: output lacks '$pattern': $out"
  if [ -n "${TOKEN:-}" ] && grep -qF -- "$TOKEN" <<<"$out"; then fail "$name: token echoed"; fi
  pass "$name: $(grep -- "$pattern" <<<"$out" | head -n 1)"
}

devices() { curl -fsS -b /tmp/cookies "$WEB/api/v1/devices"; }
online_count() { devices | grep -o '"status":"online"' | wc -l; }
device_online() { [ "$(online_count)" -ge 1 ]; }
start_agent() { # emulate systemd: run the unit's ExecStart
  local exec_start
  exec_start=$(sed -n 's/^ExecStart=//p' "$UNIT")
  # shellcheck disable=SC2086 # ExecStart is a command line to split
  $exec_start >>/tmp/agent.log 2>&1 &
  AGENT_PID=$!
}
stop_agent() {
  kill "$AGENT_PID" 2>/dev/null || true
  wait "$AGENT_PID" 2>/dev/null || true
}

t_start=$(ms)
log "setup: tools, release server, hub"
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends curl ca-certificates busybox >/dev/null
busybox httpd -p 127.0.0.1:8000 -h /srv
HEARTH_ADMIN_PASSWORD=$PASSWORD /build/hearth hub --data-dir /tmp/hub --assets-dir "$E2E_ASSETS" \
  --listen 127.0.0.1:7443 --http-listen 127.0.0.1:7080 >/tmp/hub.log 2>&1 &
wait_for 15 curl -fsS "$WEB/install.sh" || fail "hub did not start"
TOKEN=$(/build/hearth token create --data-dir /tmp/hub --hub-url "$HUB" | sed -n '2p' | tr -d ' ')
[ -n "$TOKEN" ] || fail "no token"
curl -fsS -c /tmp/cookies -H 'Content-Type: application/json' -d "{\"password\":\"$PASSWORD\"}" "$WEB/api/v1/login" >/dev/null
pass "setup in $(($(ms) - t_start)) ms"

log "hub serves deploy/install.sh"
curl -fsS -D /tmp/headers "$WEB/install.sh" | cmp - /deploy/install.sh || fail "served script differs"
grep -qi '^content-type: text/x-shellscript' /tmp/headers || fail "wrong content type"
pass "GET /install.sh matches, text/x-shellscript"

log "negatives"
mkdir -p /tmp/fakebin
# shellcheck disable=SC2016 # the fake uname's own "$1"/"$@"
printf '#!/bin/sh\ncase "$1" in -m) echo mips ;; *) exec /bin/uname "$@" ;; esac\n' >/tmp/fakebin/uname
chmod +x /tmp/fakebin/uname
expect_fail "unsupported arch" "unsupported architecture: mips" \
  env PATH="/tmp/fakebin:$PATH" HEARTH_INSTALL_PREFIX=/tmp/neg sh /deploy/install.sh --hub "$HUB" --token "$TOKEN"
expect_fail "checksum mismatch" "checksum mismatch" \
  env HEARTH_INSTALL_PREFIX=/tmp/neg sh /deploy/install.sh --hub "$HUB" --token "$TOKEN" --version v0.0.0-bad
[ ! -e /tmp/neg/usr/local/bin/hearth ] || fail "binary installed despite checksum mismatch"
expect_fail "missing token" "--token is required" \
  env HEARTH_INSTALL_PREFIX=/tmp/neg sh /deploy/install.sh --hub "$HUB"
expect_fail "plain-http hub" "must be an https:// URL" \
  env HEARTH_INSTALL_PREFIX=/tmp/neg sh /deploy/install.sh --hub "$WEB" --token "$TOKEN"
expect_fail "missing release" "does release v9.9.9 exist" \
  env HEARTH_INSTALL_PREFIX=/tmp/neg sh /deploy/install.sh --hub "$HUB" --token "$TOKEN" --version v9.9.9

log "install: curl $WEB/install.sh | sh -s -- --hub $HUB --token <token>"
t0=$(ms)
curl -fsSL "$WEB/install.sh" | sh -s -- --hub "$HUB" --token "$TOKEN" | tee /tmp/install1.log
t_installed=$(ms)
! grep -qF -- "$TOKEN" /tmp/install1.log || fail "installer echoed the token"
grep -q "installed hearth v0.0.0-e2e" /tmp/install1.log || fail "latest release not resolved"
[ -x /usr/local/bin/hearth ] || fail "binary not installed"
[ -f "$DATA/agent.crt" ] || fail "join did not write agent.crt"
[ "$(stat -c %a "$DATA")" = 700 ] || fail "data dir mode is $(stat -c %a "$DATA"), want 700"
cmp "$UNIT" /deploy/systemd/hearth-agent.service || fail "unit differs from deploy/systemd"
start_agent
wait_for 10 device_online || fail "device not online within 10 s"
t_online=$(ms)
pass "installed in $((t_installed - t0)) ms; device online $((t_online - t0)) ms after the one-liner started"
[ $((t_online - t0)) -lt 10000 ] || fail "device took longer than 10 s"
cert_sum=$(sha256sum "$DATA/agent.crt")

log "re-run (upgrade) with wget only, --from-hub, a spent token"
stop_agent
mv /usr/bin/curl /usr/bin/curl.off
ln -s /bin/busybox /usr/local/bin/wget
sh /deploy/install.sh --from-hub --hub "$HUB" --token "$TOKEN" | tee /tmp/install2.log
rm /usr/local/bin/wget
mv /usr/bin/curl.off /usr/bin/curl
grep -q "already enrolled" /tmp/install2.log || fail "re-run did not detect the identity"
grep -q "a token is not needed for an upgrade" /tmp/install2.log || fail "re-run did not explain the token"
! grep -qF -- "$TOKEN" /tmp/install2.log || fail "installer echoed the token"
[ "$cert_sum" = "$(sha256sum "$DATA/agent.crt")" ] || fail "identity changed on re-run"
start_agent
wait_for 10 device_online || fail "device not online after upgrade"
[ "$(devices | grep -o '"id":' | wc -l)" = 1 ] || fail "re-run created another device: $(devices)"
pass "identity kept, one device, online again"

log "upgrade to a prerelease with --version v0.0.1-rc.1"
stop_agent
sh /deploy/install.sh --version v0.0.1-rc.1 | tee /tmp/install3.log
grep -q "downloading hearth_0.0.1-rc.1_linux_" /tmp/install3.log || fail "prerelease asset not used"
[ "$cert_sum" = "$(sha256sum "$DATA/agent.crt")" ] || fail "identity changed on prerelease upgrade"
start_agent
wait_for 10 device_online || fail "device not online after prerelease upgrade"
pass "prerelease installed by tag, identity kept"

log "--uninstall keeps data"
stop_agent
sh /deploy/install.sh --uninstall
[ ! -e /usr/local/bin/hearth ] || fail "binary still present"
[ ! -e "$UNIT" ] || fail "unit still present"
[ -f "$DATA/agent.crt" ] || fail "--uninstall deleted the identity"
pass "binary and unit removed, $DATA kept"

log "--purge deletes data"
sh /deploy/install.sh --purge
[ ! -e "$DATA" ] || fail "--purge kept $DATA"
pass "$DATA removed"

printf '\nALL PASSED in %d ms\n' "$(($(ms) - t_start))"
