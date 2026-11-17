# T5 — Agent core

**Branch:** `t5-agent-core` · **Depends on:** T3

## Goal
A tiny, resilient agent that connects, reports facts and heartbeats.

## Scope
- `hearth agent run` (used by the service unit): loads identity from the data dir, opens the mTLS stream.
- Reconnect with exponential backoff + jitter (1 s → 60 s cap); never exits on network errors.
- Facts via gopsutil on connect and every 10 min: OS, arch, kernel, CPU, RAM, disks, interfaces (MAC, IPs), uptime.
- Heartbeat every 10 s (interval overridable by `Welcome`).
- Graceful shutdown on SIGINT/SIGTERM.
- Linux and macOS supported; Windows compiles (no-op where unsupported).

## Done when
- Integration test: agent connects to a test hub, hub restarts, agent reconnects within 5 s.
- Memory test: agent runs for 60 s idle under the test harness with RSS < 20 MB (Linux CI).
- `GOOS=linux GOARCH=arm GOARM=7` build succeeds (Pi Zero 2 / older Pis).
