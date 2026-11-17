# T1 — Repository scaffold

**Branch:** `t1-scaffold` · **Depends on:** nothing · **Unblocks:** everything

## Goal
A buildable, linted, CI-checked skeleton that matches the layout in `CLAUDE.md`.

## Scope
- Go module `github.com/gvart/hearth`; `cmd/hearth/main.go` with cobra root + `version` command
  (version, commit, date injected via `-ldflags`).
- Empty packages with a `doc.go` each: `internal/{hub,agent,pki,store,policy}`, `pkg/sdk`.
- `web/`: Vite + React + TypeScript app with a placeholder page; `internal/hub/webui` embeds `web/dist`
  via `embed.FS` (build tag or fallback page when dist is missing so `go build` works without node).
- `Taskfile.yml` with `build`, `test`, `lint`, `proto` (placeholder), `e2e` (placeholder), `dev`.
- `.golangci.yml` (reasonable defaults: govet, staticcheck, errcheck, gosec, revive, gofumpt).
- GitHub Actions `ci.yml`: lint + test + build matrix linux/darwin × amd64/arm64, `CGO_ENABLED=0`.
- DCO check workflow (or the DCO GitHub App note in README).
- `LICENSE` (AGPL-3.0 full text), `pkg/LICENSE` (Apache-2.0), SPDX headers on Go files.
- `.gitignore`, `.editorconfig`, `CONTRIBUTING.md` (DCO, Conventional Commits, how to run tasks).

## Out of scope
Any real hub/agent logic, protobuf, database.

## Done when
- `task build && ./bin/hearth version` prints version info locally.
- CI is green on the PR for all four targets.
- `task lint` passes with zero findings.
