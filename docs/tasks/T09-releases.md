# T9 — Releases

**Branch:** `t9-releases` · **Depends on:** T5 · **Parallel with:** T8

## Goal
Tagging `vX.Y.Z` produces everything a user needs.

## Scope
- `.goreleaser.yaml`: binaries for linux (amd64, arm64, armv7), darwin (amd64, arm64), windows (amd64);
  web UI built before Go build; ldflags version info; `checksums.txt`.
- Multi-arch container image for the hub on GHCR (`ghcr.io/gvart/hearth`), distroless/static base, non-root.
- `release.yml` workflow on tag push.
- Changelog generated from Conventional Commits.
- Cosign keyless signing of checksums and image (optional if it slows the task; then open an issue).

## Done when
- Pushing a `v0.0.1-rc.1` tag creates a GitHub release with all assets and an image on GHCR.
- `docker run ghcr.io/gvart/hearth:v0.0.1-rc.1 version` works on amd64 and arm64.
