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
export HEARTH_RELEASES_URL=http://127.0.0.1:8000/releases.json
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
# The agent port listens on every interface: the UI's command, made from a
# browser at 127.0.0.1, names the hub by its first certificate name that is
# not loopback: with no --host, the container's LAN address (its hostname is a
# bare name other devices could not resolve).
HEARTH_ADMIN_PASSWORD=$PASSWORD /build/hearth hub --data-dir /tmp/hub --assets-dir "$E2E_ASSETS" \
  --listen :7443 --http-listen 127.0.0.1:7080 >/tmp/hub.log 2>&1 &
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
# A stub cosign: logs its argv and whether it runs next to the files it
# names (install.sh deletes them on exit), then exits with STUB_COSIGN_EXIT.
mkdir -p /tmp/cosign-bin
cat >/tmp/cosign-bin/cosign <<'EOF'
#!/bin/sh
{
  if [ -f checksums.txt ] && [ -f checksums.txt.sigstore.json ]; then echo files-here; else echo files-missing; fi
  printf '%s\n' "$@"
} >/tmp/cosign.args
exit "${STUB_COSIGN_EXIT:-0}"
EOF
chmod +x /tmp/cosign-bin/cosign
# What install.sh must run, one argument per line.
cat >/tmp/cosign.want <<'EOF'
verify-blob
--bundle
checksums.txt.sigstore.json
--certificate-identity-regexp
^https://github\.com/gvart/Hearth/\.github/workflows/release\.yml@refs/tags/v
--certificate-oidc-issuer
https://token.actions.githubusercontent.com
checksums.txt
EOF
check_cosign_args() { # name
  [ -f /tmp/cosign.args ] || fail "$1: cosign was not run"
  tail -n +2 /tmp/cosign.args | diff /tmp/cosign.want - || fail "$1: cosign args differ"
  [ "$(head -n 1 /tmp/cosign.args)" = files-here ] || fail "$1: cosign did not run next to checksums.txt and its bundle"
  rm -f /tmp/cosign.args
}
mkdir -p /tmp/fakebin
# shellcheck disable=SC2016 # the fake uname's own "$1"/"$@"
printf '#!/bin/sh\ncase "$1" in -m) echo mips ;; *) exec /bin/uname "$@" ;; esac\n' >/tmp/fakebin/uname
chmod +x /tmp/fakebin/uname
expect_fail "unsupported arch" "unsupported architecture: mips" \
  env PATH="/tmp/fakebin:$PATH" HEARTH_INSTALL_PREFIX=/tmp/neg HEARTH_TOKEN="$TOKEN" sh /deploy/install.sh --hub "$HUB"
expect_fail "checksum mismatch" "checksum mismatch" \
  env HEARTH_INSTALL_PREFIX=/tmp/neg HEARTH_TOKEN="$TOKEN" sh /deploy/install.sh --hub "$HUB" --version v0.0.0-bad
[ ! -e /tmp/neg/usr/local/bin/hearth ] || fail "binary installed despite checksum mismatch"
expect_fail "bad signature" "signature of checksums.txt does not verify" \
  env PATH="/tmp/cosign-bin:$PATH" STUB_COSIGN_EXIT=1 HEARTH_INSTALL_PREFIX=/tmp/neg HEARTH_TOKEN="$TOKEN" \
  sh /deploy/install.sh --hub "$HUB" --version v0.0.1-rc.1
check_cosign_args "bad signature"
! grep -q "downloading hearth_" <<<"$out" || fail "bad signature: downloaded the archive anyway"
[ ! -e /tmp/neg/usr/local/bin/hearth ] || fail "binary installed despite a bad signature"
expect_fail "unsigned release with cosign" "could not download .*/checksums.txt.sigstore.json" \
  env PATH="/tmp/cosign-bin:$PATH" HEARTH_INSTALL_PREFIX=/tmp/neg HEARTH_TOKEN="$TOKEN" \
  sh /deploy/install.sh --hub "$HUB"
[ ! -e /tmp/cosign.args ] || fail "unsigned release with cosign: cosign ran without a bundle"
[ ! -e /tmp/neg/usr/local/bin/hearth ] || fail "binary installed from an unsigned release"
expect_fail "missing token" "pass HEARTH_TOKEN=<token>" \
  env HEARTH_INSTALL_PREFIX=/tmp/neg sh /deploy/install.sh --hub "$HUB"
# The same secret and CA pin, in the hearth1 form that names no hub.
NOHUB_TOKEN=$(printf '%s' "$TOKEN" | awk -F. '{ print "hearth1." $2 "." $3 }')
expect_fail "token naming no hub, no --hub" "the token names no hub: pass --hub" \
  env HEARTH_INSTALL_PREFIX=/tmp/neg HEARTH_TOKEN="$NOHUB_TOKEN" sh /deploy/install.sh
! grep -qF -- "$NOHUB_TOKEN" <<<"$out" || fail "token naming no hub: token echoed"
! grep -q "downloading" <<<"$out" || fail "token naming no hub: downloaded before failing"
# --hub overrides the token's hub, and is checked.
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

log "install as a sudo user with the Add device dialog's command"
# The command exactly as POST /api/v1/tokens gives it to the UI. The hub runs
# release-like version v0.0.0-e2e, so the command fetches install.sh of that
# tag from GitHub and pins the agent to it. It names no hub: the token does.
curl -fsS -b /tmp/cookies -H 'Content-Type: application/json' -d '{}' "$WEB/api/v1/tokens" >/tmp/token.json
TOKEN=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' /tmp/token.json)
UI_CMD=$(sed -n 's/.*"install_command":"\([^"]*\)".*/\1/p' /tmp/token.json)
RAW_SCRIPT=https://raw.githubusercontent.com/gvart/Hearth/v0.0.0-e2e/deploy/install.sh
want_cmd="curl -fsSL $RAW_SCRIPT | HEARTH_TOKEN=$TOKEN sh -s -- --version v0.0.0-e2e"
[ -n "$TOKEN" ] && [ "$UI_CMD" = "$want_cmd" ] || fail "install_command $(cat /tmp/token.json) is not the one-liner pinned to the hub version"
# Tag v0.0.0-e2e does not exist on GitHub: fetch the same script (compared
# with deploy/install.sh above) from the hub instead. Nothing else changes.
UI_CMD=${UI_CMD/"$RAW_SCRIPT"/"$WEB/install.sh"}
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
# alice's shell reads the UI's one-liner on stdin, as if pasted, so the token
# is in no argv; the one-liner puts it in the environment of the installer's sh.
printf '%s\n' "$UI_CMD" | runuser -u alice -- sh 2>&1 | tee /tmp/install1.log
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
grep -q "cosign is not installed: the release signature was not checked, only SHA-256 (install cosign" /tmp/install1.log ||
  fail "installer did not say the signature was not checked"
grep -q "installed hearth v0.0.0-e2e" /tmp/install1.log || fail "hub version not installed"
grep -q "enrolling with the hub the token names" /tmp/install1.log || fail "installer did not take the hub from the token"
[ "$(cat "$DATA/hub_url")" = "https://$(hostname -i | cut -d' ' -f1):7443" ] || fail "hub_url is $(cat "$DATA/hub_url"), want the token's https://$(hostname -i | cut -d' ' -f1):7443"
! grep -q "looking up the latest release" /tmp/install1.log || fail "pinned install looked up the latest release"
[ -x /usr/local/bin/hearth ] || fail "binary not installed"
[ -f "$DATA/agent.crt" ] || fail "join did not write agent.crt"
[ "$(stat -c %a "$DATA")" = 700 ] || fail "data dir mode is $(stat -c %a "$DATA"), want 700"
cmp "$UNIT" /deploy/systemd/hearth-agent.service || fail "unit differs from deploy/systemd"
# The token was not made hub-eligible: the device stays an agent, no hub.
grep -q "stays an agent, not a hub" /tmp/install1.log || fail "installer did not say the device stays an agent"
[ ! -e /var/lib/hearth/hub/join ] || fail "a join file without a hub-eligible token"
[ ! -e /etc/systemd/system/hearth-hub.service ] || fail "a hub unit without a hub to run"
start_agent
wait_for 10 device_online || fail "device not online within 10 s"
t_online=$(ms)
pass "installed in $((t_installed - t0)) ms; device online $((t_online - t0)) ms after the one-liner started"
[ $((t_online - t0)) -lt 10000 ] || fail "device took longer than 10 s"
cert_sum=$(sha256sum "$DATA/agent.crt")

log "re-run (upgrade) with wget only, --from-hub (no signature bundle there), cosign, a spent token"
stop_agent
mv /usr/bin/curl /usr/bin/curl.off
ln -s /bin/busybox /usr/local/bin/wget
PATH="/tmp/cosign-bin:$PATH" sh /deploy/install.sh --from-hub --hub "$HUB" --token "$TOKEN" 2>&1 | tee /tmp/install2.log
rm /usr/local/bin/wget
mv /usr/bin/curl.off /usr/bin/curl
grep -q "already enrolled" /tmp/install2.log || fail "re-run did not detect the identity"
grep -q "a token is not needed for an upgrade" /tmp/install2.log || fail "re-run did not explain the token"
grep -q "warning: --token exposes the token to other local users" /tmp/install2.log || fail "--token did not warn"
! grep -qF -- "$TOKEN" /tmp/install2.log || fail "installer echoed the token"
grep -q "the hub has no checksums.txt.sigstore.json in its --assets-dir: the release signature was not checked" /tmp/install2.log ||
  fail "--from-hub without a bundle did not say the signature was not checked"
[ ! -e /tmp/cosign.args ] || fail "--from-hub: cosign ran without a bundle"
[ "$cert_sum" = "$(sha256sum "$DATA/agent.crt")" ] || fail "identity changed on re-run"
start_agent
wait_for 10 device_online || fail "device not online after upgrade"
[ "$(devices | grep -o '"id":' | wc -l)" = 1 ] || fail "re-run created another device: $(devices)"
pass "identity kept, one device, online again"

log "upgrade while only pre-releases exist: the newest, a signed prerelease, cosign verifying"
stop_agent
# Like GitHub while every release is a pre-release: /releases/latest is 404.
PATH="/tmp/cosign-bin:$PATH" HEARTH_LATEST_URL=http://127.0.0.1:8000/no-stable-release.json \
  sh /deploy/install.sh | tee /tmp/install3.log
grep -q "found no stable release; looking up the newest release, pre-releases included" /tmp/install3.log ||
  fail "no fallback to the newest pre-release"
grep -q "downloading hearth_0.0.1-rc.1_linux_" /tmp/install3.log || fail "prerelease asset not used"
grep -q "signature OK" /tmp/install3.log || fail "signature not reported as checked"
check_cosign_args "good signature"
[ "$cert_sum" = "$(sha256sum "$DATA/agent.crt")" ] || fail "identity changed on prerelease upgrade"
start_agent
wait_for 10 device_online || fail "device not online after prerelease upgrade"
pass "newest prerelease installed after cosign verify-blob with the expected args, identity kept"

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

log "a hub-eligible token makes this capable device a hub; --agent-only keeps it an agent"
# The login above entered the password, so the hub token needs no re-auth now.
hub_token() {
  curl -fsS -b /tmp/cookies -H 'Content-Type: application/json' -d '{"hub":true}' "$WEB/api/v1/tokens" |
    sed -n 's/.*"token":"\([^"]*\)".*/\1/p'
}
HUB_DATA=/var/lib/hearth/hub
HUB_UNIT=/etc/systemd/system/hearth-hub.service
TOKEN=$(hub_token)
[ -n "$TOKEN" ] || fail "no hub token"
HEARTH_TOKEN=$TOKEN sh /deploy/install.sh 2>&1 | tee /tmp/install4.log
! grep -qF -- "$TOKEN" /tmp/install4.log || fail "installer echoed the token"
grep -q "This device becomes a hub (.*master.*)" /tmp/install4.log || fail "a capable device did not become a hub"
[ "$(stat -c %a "$HUB_DATA/join")" = 600 ] || fail "join file mode is $(stat -c %a "$HUB_DATA/join" 2>&1), want 600"
! grep -qF -- "$TOKEN" "$HUB_DATA/join" || fail "the join file holds the enrollment token"
cmp "$HUB_UNIT" /deploy/systemd/hearth-hub.service || fail "hub unit differs from deploy/systemd"
[ -f "$UNIT" ] || fail "no agent unit next to the hub's"
# A re-run with --agent-only takes the hub's service away, not its data.
sh /deploy/install.sh --agent-only 2>&1 | tee /tmp/install4b.log
grep -q "agent-only: stopped and removed the hub service" /tmp/install4b.log || fail "--agent-only re-run kept the hub"
[ ! -e "$HUB_UNIT" ] || fail "--agent-only re-run: the hub unit is still there"
[ -f "$HUB_DATA/join" ] || fail "--agent-only re-run deleted the hub's data"
[ -f "$UNIT" ] || fail "--agent-only re-run: no agent unit"
sh /deploy/install.sh --purge
[ ! -e "$HUB_DATA" ] || fail "--purge kept $HUB_DATA"
[ ! -e "$HUB_UNIT" ] || fail "--purge kept the hub unit"
pass "join file 0600, hub unit as in deploy/systemd; --agent-only re-run removes the unit, keeps the data; --purge both"

TOKEN=$(hub_token)
HEARTH_TOKEN=$TOKEN sh /deploy/install.sh --agent-only 2>&1 | tee /tmp/install5.log
! grep -q "becomes a hub" /tmp/install5.log || fail "--agent-only: became a hub"
[ ! -e "$HUB_DATA/join" ] || fail "--agent-only: a join file"
[ ! -e "$HUB_UNIT" ] || fail "--agent-only: a hub unit"
[ -f "$DATA/agent.crt" ] || fail "--agent-only: not enrolled"
sh /deploy/install.sh --purge
pass "--agent-only enrolls an agent and nothing more"

log "a device's page makes an enrolled agent a hub (--make-hub); --agent-only takes it back"
TOKEN=$(curl -fsS -b /tmp/cookies -H 'Content-Type: application/json' -d '{}' "$WEB/api/v1/tokens" |
  sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
HEARTH_TOKEN=$TOKEN sh /deploy/install.sh 2>&1 | tee /tmp/install6.log
DEV=$(sed -n 's/^Enrolled as device \([^;]*\);.*/\1/p' /tmp/install6.log)
[ -n "$DEV" ] || fail "no device ID in the install output"
[ ! -e "$HUB_UNIT" ] || fail "a plain token installed a hub unit"
# The page's answer for an agent: no member, and the command that would take a hub away.
curl -fsS -b /tmp/cookies "$WEB/api/v1/devices/$DEV/hub" >/tmp/devhub.json
! grep -q '"node_id"' /tmp/devhub.json || fail "an agent shows a hub: $(cat /tmp/devhub.json)"
grep -qF '"agent_only_command":"curl -fsSL '"$RAW_SCRIPT"' | sh -s -- --agent-only --version v0.0.0-e2e"' /tmp/devhub.json ||
  fail "agent_only_command: $(cat /tmp/devhub.json)"
# Signing in again enters the password: the join token needs it.
curl -fsS -c /tmp/cookies -H 'Content-Type: application/json' -d "{\"password\":\"$PASSWORD\"}" "$WEB/api/v1/login" >/dev/null
code=$(curl -sS -b /tmp/cookies -X POST -o /tmp/makehub.json -w '%{http_code}' "$WEB/api/v1/devices/$DEV/hub")
[ "$code" = 201 ] || fail "POST hub = $code $(cat /tmp/makehub.json)"
MH_CMD=$(sed -n 's/.*"command":"\([^"]*\)".*/\1/p' /tmp/makehub.json)
JOIN=$(sed -n 's/.*HEARTH_JOIN_TOKEN=\([^ ]*\) .*/\1/p' <<<"$MH_CMD")
want_cmd="curl -fsSL $RAW_SCRIPT | HEARTH_JOIN_TOKEN=$JOIN sh -s -- --make-hub https://$(hostname -i | cut -d' ' -f1):7443 --version v0.0.0-e2e"
[ -n "$JOIN" ] && [ "$MH_CMD" = "$want_cmd" ] || fail "make-hub command $MH_CMD, want $want_cmd"
TOKEN=$JOIN # expect_fail checks it is never echoed
expect_fail "--make-hub without a join token" "needs the join token in HEARTH_JOIN_TOKEN" sh /deploy/install.sh --make-hub "$HUB"
expect_fail "--make-hub over plain http" "must be an https:// URL" env HEARTH_JOIN_TOKEN="$JOIN" sh /deploy/install.sh --make-hub "$WEB"
expect_fail "--make-hub with --agent-only" "contradict" env HEARTH_JOIN_TOKEN="$JOIN" sh /deploy/install.sh --make-hub "$HUB" --agent-only
MH_CMD=${MH_CMD/"$RAW_SCRIPT"/"$WEB/install.sh"}
printf '%s\n' "$MH_CMD" | sh 2>&1 | tee /tmp/install7.log
! grep -qF -- "$JOIN" /tmp/install7.log || fail "installer echoed the join token"
grep -q "already enrolled" /tmp/install7.log || fail "--make-hub re-enrolled the device"
grep -q "This device becomes a hub" /tmp/install7.log || fail "--make-hub did not make the device a hub"
[ "$(stat -c %a "$HUB_DATA/join")" = 600 ] || fail "join file mode is $(stat -c %a "$HUB_DATA/join" 2>&1), want 600"
grep -qF -- "$JOIN" "$HUB_DATA/join" || fail "the join file does not hold the page's join token"
cmp "$HUB_UNIT" /deploy/systemd/hearth-hub.service || fail "hub unit differs from deploy/systemd"
[ -f "$UNIT" ] || fail "no agent unit next to the hub's"
# Make agent-only: the page shows this re-run, which takes the hub's service away.
sh /deploy/install.sh --agent-only 2>&1 | tee /tmp/install8.log
grep -q "agent-only: stopped and removed the hub service" /tmp/install8.log || fail "--agent-only re-run kept the hub"
[ ! -e "$HUB_UNIT" ] || fail "--agent-only re-run: the hub unit is still there"
# Made a hub again while the data dir still holds the removed hub: refused,
# and the old hub's service is not brought back.
mkdir -p "$HUB_DATA/cluster"
echo stale >"$HUB_DATA/ca.crt"
echo stale >"$HUB_DATA/cluster/node.crt"
printf '%s\n' "$MH_CMD" | sh 2>&1 | tee /tmp/install9.log
grep -q "holds a hub already" /tmp/install9.log || fail "--make-hub over a removed hub's data dir was not refused"
grep -q "stays an agent: it did not become a hub" /tmp/install9.log || fail "--make-hub refusal not reported"
[ ! -e "$HUB_UNIT" ] || fail "--make-hub refused, yet the old hub's unit is back"
[ -f "$UNIT" ] || fail "--make-hub refused: no agent unit"
sh /deploy/install.sh --purge
pass "the page's command makes an enrolled agent a hub, keeping its identity; --agent-only removes the hub unit"

printf '\nALL PASSED in %d ms\n' "$(($(ms) - t_start))"
