# T4 — Hub store

**Branch:** `t4-store` · **Depends on:** T1 · **Parallel with:** T2

## Goal
Persistent hub state on SQLite, CGO-free, with migrations.

## Scope
- `internal/store` opening `modernc.org/sqlite` with WAL, `busy_timeout`, foreign keys on.
- Embedded goose migrations (`internal/store/migrations/*.sql`), run on hub start.
- Tables: `devices` (id, name, hostname, os, arch, facts JSON, labels JSON, first_seen, last_seen,
  status), `tokens` (hash, labels, expires_at, used_at), `certs` (device_id, serial, revoked_at),
  `audit_log` (ts, actor_kind, actor_id, action, target, decision, result, detail JSON).
- Repository-style API with context: `Devices().Upsert/Get/List`, `Tokens().Create/Consume`, `Audit().Append/List`.
- `Audit().Append` is the only write path for audit rows; there is no update or delete.

## Done when
- Migration test runs all migrations up, then down, then up again on a temp DB.
- `Tokens().Consume` is atomic: a concurrency test with 20 goroutines consumes one token exactly once.
- `go build` still works with `CGO_ENABLED=0`.
