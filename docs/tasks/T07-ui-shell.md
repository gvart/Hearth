# T7 — UI shell

**Branch:** `t7-ui-shell` · **Depends on:** T6

## Goal
The first screen of the demo: a live device list and an "Add device" flow.

## Scope
- React + TypeScript + Vite + TanStack Query; typed API client in `web/src/api/`.
- Login page (admin password from T6).
- Devices page: table (name, status dot, OS/arch, IP, last seen, uptime), live via SSE — no polling, no reload.
- Device detail drawer: all facts.
- "Add device" dialog: calls a new `POST /api/v1/tokens`, shows the one-liner
  (`curl -fsSL <hub>/install.sh | HEARTH_TOKEN=… sh -s -- --hub …`) with a copy button and a QR code; highlights the
  new device row when it appears.
- Installable PWA manifest + icons; dark/light theme from system.
- Embedded into the binary via `embed.FS` (from T1).

## Done when
- Starting/stopping an agent flips its row's status in the open page without a reload.
- Lighthouse PWA installability passes.
- `task lint` covers eslint + tsc with zero findings.
