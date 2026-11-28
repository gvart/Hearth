# Hearth

[![CI](https://github.com/gvart/hearth/actions/workflows/ci.yml/badge.svg)](https://github.com/gvart/hearth/actions/workflows/ci.yml)

**The Home Assistant model, applied to your homelab.**

Every device in your lab — Talos/k8s nodes, Raspberry Pis, old phones, a NAS, the router, an ESP32 —
becomes an entity you can see, control and automate from one place. Local-first, self-hosted,
one Go binary.

> 🚧 Pre-alpha, built in public. Try it with [Getting started](docs/getting-started.md); follow along via the devlog at [gvart.dev](https://gvart.dev).

Documentation: **[gvart.dev/Hearth](https://gvart.dev/Hearth/)**. Its source lives in [`docs/`](docs/)
and the site is built from [`site/`](site/) (`task docs` to preview it).

## Why

Homelab tooling comes in slices: dashboards look, monitors measure, Docker/k8s UIs manage one runtime,
network mappers discover. Nothing **acts**. Hearth adds the missing layer:

- **Any device in 10 seconds** — one command, and it shows up with facts, metrics, logs and a shell.
- **Never touch it again** — turn its capabilities on and off and upgrade its agent from the web UI
  or the CLI: official releases only, checked against their checksums.
- **Automations that heal** — "Pi-hole stopped answering → restart it → fail over → ping my phone." A
  watchdog can run on the device itself, so it keeps working while the hub is down.
- **Runbooks as actions** — "Add a Talos node" becomes a guided, repeatable flow.
- **Adopt, don't replace** — plugs into your kubeconfig, talosconfig, Pi-hole, Prometheus and Proxmox,
  and reads ESPHome devices, OpenWrt routers, OPNsense firewalls and UniFi controllers (those four
  tested against fakes so far, not real hardware).
- **Agent-native** — a built-in MCP server lets Claude Code and other agents operate your lab, safely.
- **Deny by default** — every action from the UI, automations, AI or MCP passes one policy engine with an audit log.

How it fits next to Beszel, Komodo, NetAlertX and Homepage, and when to use those instead:
[Hearth and other tools](docs/comparison.md).

## Demo

Join a new device and it shows up online in the hub in **under 10 seconds**. CI holds the project to
that: on every pull request an end-to-end test starts a hub and two agents in Docker Compose, enrolls
both through the API and fails if either is not online within `DeviceVisibleWithin` of running
`hearth agent join` (defined in [`test/e2e/e2e_test.go`](test/e2e/e2e_test.go)). Run it locally with
`task e2e`.

## v0 roadmap

- [x] Single binary hub + agent, mTLS enrollment, one-line installer
- [x] Live device list, metrics, logs, web terminal
- [x] Network discovery (ARP, mDNS, Pi-hole/DHCP leases): scan, classify, then add an agent or adopt the host
- [x] Kubernetes integration (read + safe actions)
- [x] Automations (YAML in git) + guardrails + audit log
- [x] MCP server, installable PWA
- [ ] Built-in Tailscale (tsnet)

## Releases

Tagged releases (`vX.Y.Z`, with `-rc.N` tags marked as pre-releases) publish to
[GitHub Releases](https://github.com/gvart/hearth/releases):

- `hearth_<version>_<os>_<arch>.tar.gz` for linux (amd64, arm64, armv7) and darwin (amd64, arm64),
  `hearth_<version>_windows_amd64.zip` for Windows, each with the `hearth` binary at its root;
- `checksums.txt` with the SHA-256 of every archive;
- `checksums.txt.sigstore.json`, a keyless [cosign](https://github.com/sigstore/cosign) signature
  bundle for `checksums.txt` (see [Verifying releases](#verifying-releases)).

The hub also ships as a multi-arch (amd64, arm64) container image, distroless and non-root:

```sh
docker run -d --name hearth -p 7443:7443 -p 7080:7080 -v hearth:/var/lib/hearth ghcr.io/gvart/hearth:<tag>
```

Port 7443 is for agents (mTLS) and serves the web UI over HTTPS; 7080 serves the web UI over plain
HTTP, the agent installer and the hub CA certificate. Hub state lives in `/var/lib/hearth`. To install
the UI as an app and use its copy buttons from another machine, open it over HTTPS: pass
`--host <name>` for each name you browse with and trust the hub CA once per device, as described in
[docs/https.md](docs/https.md). To survive the loss of a hub, add hubs to its cluster: a capable
Linux device you add with **This device may become a hub** ticked becomes one by itself, so you can
start on a laptop and shut it later; see [docs/getting-started.md](docs/getting-started.md) and
[docs/cluster.md](docs/cluster.md).
`task release:snapshot` builds the same artifacts locally into `dist/` without publishing.

### Verifying releases

Release artifacts and images are signed keylessly with [Sigstore](https://www.sigstore.dev/) by
this repository's release workflow. Any other signer fails verification. With
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) v3 or later, first check
the checksum file's signature, then check the archives against it:

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/gvart/Hearth/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

`checksums.txt.sig` is a second signature of `checksums.txt`, made with the Hearth Ed25519 release
key, whose public half is built into the agent: an agent upgrading itself checks it, and refuses a
release without it (see [docs/security.md](docs/security.md#remote-agent-upgrades)).

The agent installer (`install.sh`) does the same when `cosign` is on its `PATH`: it checks the
signature of `checksums.txt` before trusting any checksum in it, and installs nothing if the
signature does not verify or the release has no bundle. Without cosign it says that the signature
was not checked and relies on SHA-256 alone. With `--from-hub` the hub serves whatever its
`--assets-dir` holds; put `checksums.txt.sigstore.json` there next to `checksums.txt` to have it
checked, or the installer notes that it was skipped.

The container image is signed by digest for every tag:

```sh
cosign verify ghcr.io/gvart/hearth:<tag> \
  --certificate-identity-regexp '^https://github\.com/gvart/Hearth/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Contributing

Early days — issues and ideas welcome. Work is tracked as task specs in [`docs/tasks/`](docs/tasks/).
Commits follow Conventional Commits and need a DCO sign-off (`git commit -s`), checked on every pull
request by the `DCO` workflow. See [CONTRIBUTING.md](CONTRIBUTING.md) for tooling and `task` commands.

## Support

Hearth is free and open source. Funding options will be listed here once GitHub Sponsors and
Open Collective are set up ([#56](https://github.com/gvart/hearth/issues/56)). Until then, issues,
bug reports and pull requests help most.

## License

AGPL-3.0, except `pkg/` (Apache-2.0) and `docs/spec/` (CC-BY-4.0).
