# T8 — Installer

**Branch:** `t8-installer` · **Depends on:** T5 · **Parallel with:** T9

## Goal
One command turns a fresh Linux or macOS machine into an enrolled agent.

## Scope
- `deploy/install.sh` (POSIX sh, shellcheck-clean), also served by the hub at `/install.sh`.
- Detects OS (linux/darwin) and arch (amd64, arm64, armv7); fails clearly on anything else.
- Downloads the matching release asset from GitHub (or from the hub if `--from-hub`), verifies SHA-256
  against the release checksums file.
- Installs to `/usr/local/bin/hearth`; creates data dir; installs a systemd unit (Linux) or launchd plist (macOS);
  runs `hearth agent join <hub> <token>`; starts the service.
- Idempotent: re-running upgrades the binary and keeps the identity.
- `--uninstall` removes the service and binary (keeps data unless `--purge`).

## Done when
- Manual check on a fresh Debian 12 VM, a Raspberry Pi (arm64) and macOS: device visible in the UI in < 10 s.
- `shellcheck deploy/install.sh` is clean in CI.
