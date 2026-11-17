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

# expect_fail NAME PATTERN command... runs command, which must fail and print
# PATTERN. Leaves the command's output in $out.
expect_fail() {
  local name=$1 pattern=$2
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
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends curl ca-certificates busybox sudo >/dev/null
# A non-root user with sudo, which logs every command line it runs.
useradd -m alice
printf 'Defaults logfile=/var/log/sudo.log\nalice ALL=(ALL) NOPASSWD: ALL\n' >/etc/sudoers.d/e2e
chmod 0440 /etc/sudoers.d/e2e
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
  env PATH="/tmp/fakebin:$PATH" HEARTH_INSTALL_PREFIX=/tmp/neg HEARTH_TOKEN="$TOKEN" sh /deploy/install.sh --hub "$HUB"
expect_fail "checksum mismatch" "checksum mismatch" \
  env HEARTH_INSTALL_PREFIX=/tmp/neg HEARTH_TOKEN="$TOKEN" sh /deploy/install.sh --hub "$HUB" --version v0.0.0-bad
[ ! -e /tmp/neg/usr/local/bin/hearth ] || fail "binary installed despite checksum mismatch"
expect_fail "missing token" "pass HEARTH_TOKEN=<token>" \
  env HEARTH_INSTALL_PREFIX=/tmp/neg sh /deploy/install.sh --hub "$HUB"
expect_fail "plain-http hub" "must be an https:// URL" \
  env HEARTH_INSTALL_PREFIX=/tmp/neg HEARTH_TOKEN="$TOKEN" sh /deploy/install.sh --hub "$WEB"
expect_fail "missing release" "does release v9.9.9 exist" \
  env HEARTH_INSTALL_PREFIX=/tmp/neg HEARTH_TOKEN="$TOKEN" sh /deploy/install.sh --hub "$HUB" --version v9.9.9
# --token wins over HEARTH_TOKEN: a bogus --token must fail to enroll even
# though HEARTH_TOKEN holds a valid (and so unspent) token.
TOKEN2=$(/build/hearth token create --data-dir /tmp/hub --hub-url "$HUB" | sed -n '2p' | tr -d ' ')
[ -n "$TOKEN2" ] || fail "no second token"
expect_fail "--token over HEARTH_TOKEN" "both --token and HEARTH_TOKEN are set; using --token" \
  env HEARTH_INSTALL_PREFIX=/tmp/both HEARTH_TOKEN="$TOKEN2" sh /deploy/install.sh --hub "$HUB" --token not-a-token
grep -q "enrollment failed" <<<"$out" || fail "--token over HEARTH_TOKEN: enrolled with HEARTH_TOKEN: $out"
! grep -qF -- "$TOKEN2" <<<"$out" || fail "--token over HEARTH_TOKEN: token echoed"
[ ! -e /tmp/both/var/lib/hearth/agent/agent.crt ] || fail "--token over HEARTH_TOKEN: enrolled"

log "install as a sudo user: curl $WEB/install.sh | HEARTH_TOKEN=<token> sh -s -- --hub $HUB"
# Record every process holding the token in its argv or its environment while
# the installer runs. grep reads the token from a file so its own argv stays clean.
printf '%s\n' "$TOKEN" >/tmp/token.pat
: >/tmp/argv-hits.log
: >/tmp/env-hits.log
(
  set +e # processes come and go between grep and tr
  while [ ! -e /tmp/scan.stop ]; do
    grep -a -l -F -f /tmp/token.pat /proc/[0-9]*/cmdline 2>/dev/null | while read -r f; do
      tr '\0' ' ' <"$f" 2>/dev/null && echo
    done >>/tmp/argv-hits.log
    grep -a -l -F -f /tmp/token.pat /proc/[0-9]*/environ 2>/dev/null | while read -r f; do
      tr '\0' ' ' <"${f%/environ}/cmdline" 2>/dev/null && echo
    done >>/tmp/env-hits.log
  done
  exit 0
) &
scan_pid=$!
t0=$(ms)
# The token reaches alice's shell through its environment; the shell moves it
# into a plain variable so that curl does not inherit it, and then runs the
# UI's one-liner, which puts it in the environment of the installer's own sh.
# shellcheck disable=SC2016 # expanded by alice's shell
HEARTH_E2E_TOKEN=$TOKEN runuser -u alice -- sh -c \
  't=$HEARTH_E2E_TOKEN; unset HEARTH_E2E_TOKEN; curl -fsSL "$0/install.sh" | HEARTH_TOKEN=$t sh -s -- --hub "$1"' \
  "$WEB" "$HUB" 2>&1 | tee /tmp/install1.log
t_installed=$(ms)
touch /tmp/scan.stop
wait "$scan_pid"
! grep -qF -- "$TOKEN" /tmp/install1.log || fail "installer echoed the token"
! grep -q -- "--token" /tmp/install1.log || fail "installer warned about --token without one"
grep -q "using sudo" /tmp/install1.log || fail "installer did not use sudo"
grep -q "agent join" /var/log/sudo.log || fail "join did not run through sudo"
! grep -qF -- "$TOKEN" /var/log/sudo.log || fail "token in sudo's log: $(cat /var/log/sudo.log)"
[ ! -s /tmp/argv-hits.log ] || fail "token in the argv of a process: $(sort -u /tmp/argv-hits.log)"
# Only the launching processes hold it in their environment (a forked subshell
# of the installer shows the installer's argv): the installer unsets
# HEARTH_TOKEN before it runs anything, so curl, tar, sudo and hearth never get it.
if grep -v -e '^runuser ' -e '^sh -c ' -e '^sh -s -- ' /tmp/env-hits.log | grep -q .; then
  fail "token in the environment of a child process: $(sort -u /tmp/env-hits.log)"
fi
grep -q '^sh -s -- ' /tmp/env-hits.log || fail "environment scan never saw the installer's sh; is the scan working? $(sort -u /tmp/env-hits.log)"
pass "token in no process's argv, in no child's environment, not in sudo's log ($(grep -c . /tmp/env-hits.log) env samples)"
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
sh /deploy/install.sh --from-hub --hub "$HUB" --token "$TOKEN" 2>&1 | tee /tmp/install2.log
rm /usr/local/bin/wget
mv /usr/bin/curl.off /usr/bin/curl
grep -q "already enrolled" /tmp/install2.log || fail "re-run did not detect the identity"
grep -q "a token is not needed for an upgrade" /tmp/install2.log || fail "re-run did not explain the token"
grep -q "warning: --token exposes the token to other local users" /tmp/install2.log || fail "--token did not warn"
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
