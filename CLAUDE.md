# Hearth — agent instructions

Hearth is an open-source control plane for homelabs: the Home Assistant model applied to compute.
Every device (k8s/Talos node, Raspberry Pi, old phone, NAS, router, microcontroller) becomes an
entity you can see, control and automate. Local-first, self-hosted, single Go binary.

Read this file fully before starting any task. Task specs live in `docs/tasks/`.

## Product principles (non-negotiable)

1. **Adopt, don't replace.** Hearth plugs into an existing lab (kubeconfig, talosconfig, Pi-hole,
   Prometheus). Never require users to migrate their stack.
2. **Act, not just look.** Automations and runbooks are the product. Dashboards are a side effect.
3. **Deny by default.** Every action — UI, CLI, automation, AI, MCP — goes through `internal/policy`.
   No code path may execute anything on a device without a policy decision and an audit log entry.
4. **Tiny on the edge.** The agent must idle under 25 MB RSS and near-zero CPU. Measure it.
5. **Ship the demo.** v0's headline: one command on a fresh device → visible in the UI in < 10 s.
   Anything that doesn't serve v0 scope goes behind an issue, not into the PR.

## Architecture

```
clients (React PWA, CLI, MCP clients)
        │  LAN or tailnet (tsnet)
        ▼
hub ── api + mcp ── policy ── automations/runbooks ── integrations ── store (SQLite)
        ▲                                                   │
        │ agents dial out (mTLS, Connect-RPC stream)        ▼ pull (k8s, Talos, Pi-hole, Prometheus)
agents (linux/macOS/windows/android)      network scan (ARP, mDNS, DHCP leases)
```

- One binary, two modes: `hearth hub` and `hearth agent`. Any node can become the hub.
- Agents always dial out to the hub. No inbound ports on devices.
- Hub state: SQLite (WAL). Pure Go driver only — the build must stay `CGO_ENABLED=0`.

## Repository layout

```
cmd/hearth/            main; cobra commands: hub, agent, token, version, ...
internal/hub/          hub server, device registry, HTTP/SSE API
internal/agent/        agent runtime, facts, heartbeat, exec
internal/proto/        generated protobuf/Connect code (do not edit by hand)
internal/pki/          CA, CSR signing, enrollment tokens
internal/store/        SQLite access + goose migrations
internal/policy/       action classes, decisions, audit log
internal/discovery/    network discovery: ARP sweep, mDNS, OUI vendors, DHCP lease import (unmanaged hosts)
internal/cluster/      Raft replication of the hub store (hashicorp/raft), hub join, mTLS transport
internal/s3/           minimal SigV4 S3 client (put, list, delete) for scheduled backups
internal/plugins/      exec plugins: child processes speaking JSON lines over stdio (docs/plugins.md)
internal/mqtt/         embedded MQTT broker (mochi-mqtt): TLS, device-cert or password auth, topic ACLs
internal/hubconfig/    config documents (policy, notify, automations, runbooks) in the store: live apply, import/export
pkg/sdk/               public agent/plugin SDK — Apache-2.0 licensed
proto/                 .proto sources
web/                   Vite + React + TypeScript UI, embedded via embed.FS
deploy/                install.sh, systemd/launchd units
docs/                  user docs (*.md, rendered by site/), design notes, task specs (docs/tasks/)
site/                  docs site: Astro Starlight; publishes the docs/*.md listed in site/src/pages.mjs
test/e2e/              end-to-end tests (compose: hub + agents)
examples/              example exec plugins (Go, Python), exercised by internal/plugins tests
```

## Stack

- Go (latest stable). Stdlib first; small, well-known deps only.
- CLI: cobra. Logging: `log/slog` (JSON in prod, text in dev).
- RPC: protobuf + Connect-RPC (`connectrpc.com/connect`), generated with buf.
- DB: `modernc.org/sqlite` + `pressly/goose` migrations (embedded SQL files).
- Host facts/metrics: `gopsutil`.
- UI: React + TypeScript + Vite + TanStack Query. No component library lock-in decisions without an issue.
- Releases: goreleaser. Lint: golangci-lint. Tasks: Taskfile (`task`).

## Commands

```
task build        # build web + binary
task test         # go test ./... -race
task test:web     # web UI tests (node --test): the automation editor's YAML round trip
task lint         # SPDX header check + golangci-lint + eslint + tsc
task proto        # buf lint + buf generate (into internal/proto)
task e2e          # compose-based end-to-end test of the headline demo
task e2e:cluster  # compose-based end-to-end test of 3-hub cluster failover
task e2e:install  # install.sh end to end in a Debian 12 container (Docker)
task dev          # web UI dev server with hot reload (Vite)
task docs         # docs site dev server with hot reload (site/, Astro Starlight)
task docs:build   # build the static docs site into site/dist
task release:snapshot  # goreleaser snapshot: all archives + image into dist/, no publish
```

Keep this list in sync with `Taskfile.yml`. If you add a task, document it here.

## Coding conventions

- Errors: wrap with context (`fmt.Errorf("enroll agent %s: %w", id, err)`); no panics outside `main`.
- Context: every blocking call takes a `context.Context`; respect cancellation.
- Concurrency: no goroutine without an owner that stops it. Prefer `errgroup`.
- Config: flags > env (`HEARTH_*`) > file. Defaults must work for a single-node homelab.
- No global state except the logger. Constructors take dependencies explicitly.
- Public API (`pkg/`) is a contract: no breaking changes without a design note in `docs/`.
- Frontend: typed API client generated or hand-written in one place (`web/src/api/`); no fetch calls scattered in components.

## Security rules

- Never log secrets, tokens, private keys or full certificates.
- Enrollment tokens: single-use, short TTL, stored hashed.
- mTLS everywhere between hub and agents, and between hubs; the hub CA key never leaves a hub voter's data
  dir (0600), except inside an encrypted backup archive created by an authenticated admin through policy and
  audited, or by a scheduled hub backup when the operator opts in with `--backup-include-ca` (also through
  policy and audited); it is replicated only over the pinned mTLS join channel and, during a hub CA rotation,
  over the pinned mTLS `FetchCAKey` channel (policy-checked and audited, refusals too). A CA key never goes
  into the store, the Raft log or a snapshot.
- Agent-side config is the capability ceiling; the hub can never grant more than the device allows.
- Any new action type must declare its class (`read` / `safe` / `dangerous`) in `internal/policy`.
- Shell-outs: no string concatenation into shells; use `exec.Command` with args.

## Testing

- Every PR: unit tests for new logic, `go test -race` green, lint green.
- Table-driven tests; use `t.TempDir()` for files and an in-memory or temp SQLite for store tests.
- Anything touching enrollment, PKI or policy needs negative tests (expired, reused, revoked, denied).
- `test/e2e` guards the headline demo: a device must appear in < 10 s. Never weaken that assertion to make CI pass.

## Workflow for agents

- One task = one branch = one PR. Branch name: `t<N>-<slug>` (e.g. `t3-enrollment`).
- Start by restating the task's "Done when" criteria; finish by showing they pass.
- Keep PRs small and focused. Unrelated refactors go in a separate PR.
- Commits follow Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`) and are signed off (`git commit -s`, DCO).
- If a decision isn't covered here or in the task spec, pick the simplest option, note it in the PR description under "Decisions", and move on.
- PR descriptions follow `.github/pull_request_template.md` (What / Done when / Decisions / Checklist). `gh pr create --body` skips the template, so fill it in yourself. No AI attribution footers or co-author trailers.
- Do not add features outside the task's scope. Open an issue instead.

## Licensing

- Everything is AGPL-3.0 except `pkg/` (Apache-2.0) and `docs/spec/` (CC-BY-4.0).
- New files in `pkg/` carry an `SPDX-License-Identifier: Apache-2.0` header; other Go files `AGPL-3.0-only`.
