# T6 — Device registry and API

**Branch:** `t6-registry` · **Depends on:** T3, T4 · **Parallel with:** T5

## Goal
The hub knows which devices exist and whether they are online, and streams changes to clients.

## Scope
- On `Hello`: upsert device from facts. On heartbeat: update `last_seen`.
- Status machine: `online` → `offline` after 30 s without heartbeat (one ticker, not a goroutine per device);
  `offline` → `online` on next heartbeat. Status changes are events on an in-process bus.
- HTTP API (JSON, `/api/v1`): `GET /devices`, `GET /devices/{id}`, `GET /events` (SSE stream of
  `device.online`, `device.offline`, `device.updated`).
- Admin auth for v0: single admin password set on first start (argon2id hash in store), session cookie.
  Keep it minimal; it gets replaced later.

## Done when
- Unit tests for every status transition, using a fake clock.
- SSE test: subscribe, connect an agent, receive `device.online` within 1 s; stop it, receive `device.offline` after the timeout.
- Unauthenticated API calls get 401.
