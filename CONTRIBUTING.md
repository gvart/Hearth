# Contributing to Hearth

Thanks for helping build Hearth! This document covers the tooling, the workflow and the two
rules every commit must follow: **Conventional Commits** and a **DCO sign-off**.

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| [Go](https://go.dev/dl/) | 1.26+ | Builds are pure Go (`CGO_ENABLED=0`). `go test -race` needs a C compiler. |
| [Node.js](https://nodejs.org/) | 22.12+ (CI uses 24) | Only for the web UI. `go build` works without it. |
| [Task](https://taskfile.dev/installation/) | 3.x | `go install github.com/go-task/task/v3/cmd/task@latest` |
| [golangci-lint](https://golangci-lint.run/docs/welcome/install/) | v2.15+ | Must be built with a Go version ≥ the one in `go.mod`. |

## Common tasks

```bash
task build        # build web UI + binary into ./bin (honours GOOS/GOARCH)
task test         # go test ./... -race
task lint         # golangci-lint + eslint + tsc, zero findings required
task proto        # buf generate (placeholder until protobuf lands)
task e2e          # compose-based end-to-end tests (needs Docker)
task dev          # web UI dev server with hot reload
```

`./bin/hearth version` prints the version, commit and build date injected at link time.

A plain `go build ./cmd/hearth` also works without Node: the binary then serves a placeholder page
instead of the web UI.

To auto-format Go code: `golangci-lint fmt`.

## Workflow

- One task = one branch = one PR. Task specs live in [`docs/tasks/`](docs/tasks/); branch names
  follow `t<N>-<slug>` (e.g. `t3-enrollment`).
- Keep PRs small and focused. Unrelated refactors go in a separate PR; new ideas go in an issue.
- Every PR needs unit tests for new logic, and `task test` and `task lint` green.
- Anything touching enrollment, PKI or policy needs negative tests (expired, reused, revoked, denied).

## Commit messages: Conventional Commits

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `chore:`,
`docs:`, `test:`, `refactor:`, `ci:`, `build:`. Release notes are generated from them.

```
feat(agent): report uptime in heartbeat
```

## Developer Certificate of Origin (DCO)

Hearth uses the [Developer Certificate of Origin](https://developercertificate.org/) instead of a CLA.
By signing off a commit you certify that you wrote it or otherwise have the right to submit it under
the project's licenses. Sign off every commit with `-s`:

```bash
git commit -s -m "fix(hub): close SSE stream on shutdown"
```

This adds a `Signed-off-by: Your Name <you@example.com>` trailer that must match the commit author.
The `DCO` workflow checks every commit in a pull request. To fix a branch that is missing sign-offs:

```bash
git rebase --signoff main
```

## Licensing

- Everything is [AGPL-3.0-only](LICENSE) except `pkg/` ([Apache-2.0](pkg/LICENSE)) and `docs/spec/` (CC-BY-4.0).
- Every Go file starts with an SPDX header; `task lint` enforces it (`scripts/check-spdx.sh`):
  - `pkg/`: `// SPDX-License-Identifier: Apache-2.0`
  - everything else: `// SPDX-License-Identifier: AGPL-3.0-only`
