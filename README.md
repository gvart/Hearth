# Hearth

[![CI](https://github.com/gvart/hearth/actions/workflows/ci.yml/badge.svg)](https://github.com/gvart/hearth/actions/workflows/ci.yml)

**The Home Assistant model, applied to your homelab.**

Every device in your lab — Talos/k8s nodes, Raspberry Pis, old phones, a NAS, the router, an ESP32 —
becomes an entity you can see, control and automate from one place. Local-first, self-hosted,
one Go binary.

> 🚧 Pre-alpha, built in public. Nothing to install yet. Follow along via the devlog at [gvart.dev](https://gvart.dev).

## Why

Homelab tooling comes in slices: dashboards look, monitors measure, Docker/k8s UIs manage one runtime,
network mappers discover. Nothing **acts**. Hearth adds the missing layer:

- **Any device in 10 seconds** — one command, and it shows up with facts, metrics, logs and a shell.
- **Automations that heal** — "Pi-hole stopped answering → restart it → fail over → ping my phone."
- **Runbooks as actions** — "Add a Talos node" becomes a guided, repeatable flow.
- **Adopt, don't replace** — plugs into your kubeconfig, talosconfig, Pi-hole and Prometheus.
- **Agent-native** — a built-in MCP server lets Claude Code and other agents operate your lab, safely.
- **Deny by default** — every action from the UI, automations, AI or MCP passes one policy engine with an audit log.

## v0 roadmap

- [ ] Single binary hub + agent, mTLS enrollment, one-line installer
- [ ] Live device list, metrics, logs, web terminal
- [ ] Network discovery (ARP, mDNS, Pi-hole/DHCP leases)
- [ ] Kubernetes integration (read + safe actions)
- [ ] Automations (YAML in git) + guardrails + audit log
- [ ] MCP server, built-in Tailscale (tsnet), installable PWA

## Contributing

Early days — issues and ideas welcome. Work is tracked as task specs in [`docs/tasks/`](docs/tasks/).
Commits follow Conventional Commits and need a DCO sign-off (`git commit -s`), checked on every pull
request by the `DCO` workflow. See [CONTRIBUTING.md](CONTRIBUTING.md) for tooling and `task` commands.

## License

AGPL-3.0, except `pkg/` (Apache-2.0) and `docs/spec/` (CC-BY-4.0).
