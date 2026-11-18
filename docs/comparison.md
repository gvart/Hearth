---
title: Hearth and other tools
description: When to use Beszel, Komodo, NetAlertX or Homepage, when to use Hearth, and how they fit together.
---

Homelab tools each cover one part of the job. Dashboards show your services, monitors measure them,
deploy tools manage containers, network mappers find what is plugged in. Hearth is meant to be the
layer that **acts**: when something breaks, it restarts it, runs the fix and tells you, with every
step decided by policy and recorded in the audit log. It is meant to sit next to the tools you
already run, not to replace them.

This page compares Hearth with four popular tools. Hearth is **pre-alpha** (`v0.0.1-rc.N`) and the
others are mature, widely used projects. Where one of them does a job better, this page says so.
Anything Hearth does not do on `main` today is marked **planned**, with a link to its issue.

## At a glance

|                     | [Beszel](https://beszel.dev)                         | [Komodo](https://komo.do)                                          | [NetAlertX](https://docs.netalertx.com)                       | [Homepage](https://gethomepage.dev)                         | Hearth                                                                      |
| ------------------- | ---------------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------------- |
| What it is          | Server monitoring: metrics history, container stats, alerts | Build and deploy software (Docker, Compose, Swarm) across servers | Network inventory: what is on the network and what changed     | Application dashboard and start page                        | Control plane: devices, automations that act, policy and audit              |
| Runs on devices     | Agent (Go)                                           | Periphery agent                                                    | Nothing; it scans from where it runs                          | Nothing                                                     | Agent (Go), the same binary as the hub                                      |
| Metrics             | Wide range, with history                             | CPU, memory, disk per server                                       | Presence, not system metrics                                  | Through service widgets                                     | Reads your Prometheus; stores none itself                                   |
| Alerts              | On most metrics; ~27 services through Shoutrrr       | CPU, memory, disk                                                  | On network events; Apprise (80+ services), ntfy, MQTT, ...    | No                                                          | Automation triggers; ntfy, Telegram, webhooks                               |
| Takes actions       | No                                                   | Yes: deploys, builds, container start/stop, terminals, scripts     | On its own records (workflows); Wake-on-LAN plugin            | No                                                          | Yes: restart, command, webhook, Kubernetes day-two actions                  |
| Automations         | No                                                   | Procedures and TypeScript Actions; schedules, git webhooks         | Workflows on device records                                   | No                                                          | YAML triggers (device, metric, HTTP/DNS/TCP checks, schedule) to actions    |
| Kubernetes          | No                                                   | No (Docker and Swarm)                                              | No                                                            | Service discovery from Ingress annotations; pod CPU/memory  | Adopts via kubeconfig: watch, restart, scale, cordon, drain                 |
| Access control      | Multi-user, OAuth/OIDC                               | Users, roles, OAuth/OIDC, audit trail                              | Optional login password (SETPWD plugin)                       | Opt-in OIDC or password login; meant to sit behind an auth proxy | One admin account; deny-by-default policy for every action; audit log      |
| Maturity            | v0.21.2, 27k stars                                   | v2.3.4, 13k stars                                                  | v26.10.28, 7k stars                                           | v2.8.0, 34k stars                                           | v0.0.1-rc.6, pre-alpha                                                      |
| License             | MIT                                                  | GPL-3.0                                                            | GPL-3.0                                                       | GPL-3.0                                                     | AGPL-3.0 (`pkg/` Apache-2.0)                                                |

Versions and star counts as of 2026-11-18; see [Sources](#sources).

## Beszel

**What it is.** A lightweight server monitor: a hub (built on PocketBase) and a small Go agent on
each machine. The agent can connect out to the hub over a WebSocket, or the hub can reach it over
SSH. It records CPU, memory (with swap and ZFS ARC), disk usage and I/O, network, load, temperatures,
fans, GPU, battery, S.M.A.R.T. and ZFS health, Docker and Podman container stats, and network checks
(ICMP, TCP, HTTP, DNS) from the agent, all with history. Alerts go to about 27 services through
Shoutrrr. It has multiple users, OAuth/OIDC, S3 backups and a REST API, and agents for Linux,
FreeBSD, macOS, Windows, Docker and Home Assistant.

**Use Beszel when** you want to see how your machines are doing and how that changed over weeks:
graphs, history, container usage and an alert when a disk fills up. It does this far better than
Hearth, which keeps no metric history of its own and today charts only CPU, memory and root disk
for the last hour, from a Prometheus you already run.

**Use Hearth when** you want the alert to come with a fix. Beszel tells you, by design; it does not
restart a service or run a command. Hearth's automations can: a check fails, the agent restarts
the systemd unit or Docker container, and ntfy or Telegram tells you it did.

**Together.** Run both. Beszel for history and graphs, Hearth for the automations that respond.
Hearth cannot read Beszel today; importing its systems and metrics is **planned**
([#66](https://github.com/gvart/hearth/issues/66)).

## Komodo

**What it is.** A tool to build and deploy software across many servers. Komodo Core serves the UI
and API; a stateless Periphery agent on each server talks to Core over a bi-directional WebSocket,
opened by either side. It manages Docker containers (Deployments), Compose stacks from the UI, the
host or a git repo (with auto-deploy on push), Swarm services, image builds, and resource sync
(configuration as code). Procedures chain executions into stages, and Actions are TypeScript scripts
against the Komodo API; both can run on a schedule or from a git webhook. It has terminals to servers
and containers, role-based permissions, OAuth/OIDC and an audit trail, and alerts on CPU, memory and
disk.

**Use Komodo when** you deploy and update Docker workloads on several hosts and want git-driven,
repeatable deploys and builds. That is Komodo's job and it does it well; Hearth does not deploy
anything and has no plan to manage Compose stacks or builds. Komodo also has things Hearth does not
have yet: terminals (Hearth's web terminal is **planned**,
[#34](https://github.com/gvart/hearth/issues/34)), container logs (**planned**,
[#33](https://github.com/gvart/hearth/issues/33)) and multiple users.

**Use Hearth when** your lab is more than Docker hosts: Kubernetes clusters, systemd services on a
Pi, a NAS. Hearth adopts a Kubernetes cluster through its kubeconfig and takes day-two actions on it
(restart, scale, delete a pod, cordon, drain with PodDisruptionBudgets honoured); Komodo covers Docker
and Swarm. Hearth's automations are driven by what happens (a device goes offline, a check fails, a
metric runs hot), where Komodo's run on a schedule, by hand or on a git push. And every Hearth action
passes a deny-by-default policy, can be held for approval, and is limited by what the device itself
allows (`--allow-restart`, `--allow-exec`).

**Together.** Komodo deploys; Hearth watches and heals. Keep deploying your stacks with Komodo and let
a Hearth automation restart a container (`docker:NAME`) when its health check fails. There is no
direct integration; a Docker integration of Hearth's own is **planned**
([#64](https://github.com/gvart/hearth/issues/64)), and Komodo is not part of it.

## NetAlertX

**What it is.** Network visibility and asset inventory. It discovers devices with plugins (ARP scan,
ICMP, `ip neigh`, NMAP, SNMP, mDNS/NetBIOS naming) and imports them from DHCP leases, Pi-hole,
AdGuard, UniFi, MikroTik, FRITZ!Box, OpenWrt (LuCI), Omada and more. It records what changed (new
devices, offline, IP, hostname and port changes) and notifies through Apprise (80+ services), ntfy,
Pushover, Telegram, MQTT, email or webhooks. It integrates with Home Assistant, has an API (REST,
GraphQL, SSE and MCP), and workflows that update or delete device records when an event happens.
Nothing is installed on the devices.

**Use NetAlertX when** you want to know everything on your network, including the things that will
never run an agent: the TV, the smart plugs, a guest's phone. Hearth only knows devices that run its
agent or are nodes of an adopted Kubernetes cluster. Network discovery (ARP, mDNS) and Pi-hole and
DHCP lease import are **planned** ([#35](https://github.com/gvart/hearth/issues/35),
[#36](https://github.com/gvart/hearth/issues/36)), and NetAlertX will stay far ahead on breadth of
discovery and router support.

**Use Hearth when** you want to act on the machines you run: restart a service, run a command, drain a
node. NetAlertX's workflows act on its own inventory; besides the Wake-on-LAN plugin, it does not
change anything on the devices.

**Together.** NetAlertX maps the whole network; Hearth manages the machines you own. Importing
NetAlertX's devices into Hearth is **planned** ([#66](https://github.com/gvart/hearth/issues/66)).
Until then, a NetAlertX webhook or notification and a Hearth automation work side by side, not
together.

## Homepage

**What it is.** A fast, customizable application dashboard and start page, configured in YAML or
discovered from Docker labels and Kubernetes Ingress (and Gateway API, Traefik) annotations. Over 100
service widgets show data from your apps (the *arr apps, Plex, Jellyfin, Proxmox, Home Assistant,
...), with API calls proxied so keys stay on the server. It shows Docker container status and stats,
and pod CPU and memory on Kubernetes. It is meant to sit behind a reverse proxy or VPN that enforces
authentication; an opt-in OIDC or password login is available.

**Use Homepage when** you want one page with links to all your services and a glance at their state.
It looks better and integrates with far more apps than Hearth's UI, which is built for operating
devices, not for a start page.

**Use Hearth when** you want to do something about what you see: Homepage displays, Hearth acts. A
red tile on Homepage can be a Hearth automation that already restarted the service.

**Together.** Keep Homepage as your front door. Exporting Hearth's devices and services to Homepage
is **planned** ([#66](https://github.com/gvart/hearth/issues/66)).

## When Hearth is the wrong tool

Today, Hearth is not the right choice if you need:

- **metric history and rich graphs**: use Beszel, or Prometheus and Grafana;
- **Docker deploys, builds and git-driven stacks**: use Komodo;
- **a full inventory of everything on the network**: use NetAlertX;
- **a start page for your apps**: use Homepage;
- **several users with their own roles**: Hearth has one admin account;
- **a Windows or Android agent**: both are **planned**
  ([#68](https://github.com/gvart/hearth/issues/68), [#79](https://github.com/gvart/hearth/issues/79));
  agents run on Linux and macOS;
- **something stable**: Hearth is pre-alpha, and its configuration and APIs may still change.

## What Hearth does today

On `main`, Hearth has:

- a hub and agent in one Go binary; agents dial out over mutual TLS, so devices open no ports, and
  enroll with a one-line installer and a single-use token ([Getting started](getting-started.md));
- automations in YAML, kept in git: triggers on device online/offline, metric thresholds or any
  PromQL query, HTTP, DNS and TCP checks (from the hub or from a device), and cron schedules; actions
  that restart a systemd unit or Docker container, run a command, call a webhook, send a notification,
  or act on Kubernetes ([Automations](automations.md), [Notifications](notifications.md));
- one deny-by-default policy for every action, a policy file to allow, confirm or deny each class,
  approvals, dry runs, a per-device capability ceiling the hub cannot raise, and an audit log with its
  own page in the UI ([Guardrails](guardrails.md), [Security model](security.md));
- device charts and metric triggers from an existing Prometheus, read-only ([Prometheus](prometheus.md));
- Kubernetes adopted through a kubeconfig, with nothing installed in the cluster: nodes, workloads,
  pods, events, pod logs, and day-two actions ([Kubernetes](kubernetes.md));
- a three-hub cluster that survives the loss of one ([Cluster mode](cluster.md));
- an MCP server, so Claude Code and other AI assistants can see and operate the lab with scoped
  tokens, through the same policy, approvals and audit log ([MCP](mcp.md)).

**Planned** for v0 and not on `main` yet: network discovery
([#35](https://github.com/gvart/hearth/issues/35)), Pi-hole and DHCP lease import
([#36](https://github.com/gvart/hearth/issues/36)), log tail
([#33](https://github.com/gvart/hearth/issues/33)), a web terminal
([#34](https://github.com/gvart/hearth/issues/34)), built-in Tailscale
([#48](https://github.com/gvart/hearth/issues/48)) and runbooks
([#61](https://github.com/gvart/hearth/issues/61)).

## Sources

Checked on 2026-11-18 against each project's README and documentation, at the release named.

- **Beszel** v0.21.2 (2026-11-12): [README](https://github.com/henrygd/beszel),
  [What is Beszel](https://beszel.dev/guide/what-is-beszel),
  [Agent installation](https://beszel.dev/guide/agent-installation),
  [Notifications](https://beszel.dev/guide/notifications).
- **Komodo** v2.3.4 (2026-10-22): [README](https://github.com/moghtech/komodo),
  [Introduction](https://komo.do/docs/intro),
  [Connect servers](https://komo.do/docs/setup/connect-servers),
  [Procedures and Actions](https://komo.do/docs/automate/procedures),
  [Webhooks](https://komo.do/docs/automate/webhooks).
- **NetAlertX** v26.10.28 (2026-10-28): [README](https://github.com/netalertx/NetAlertX),
  [Documentation](https://docs.netalertx.com/),
  [Where NetAlertX fits](https://docs.netalertx.com/WHERE_NETALERTX_FITS/),
  [Workflows](https://docs.netalertx.com/WORKFLOWS/),
  [Security features](https://docs.netalertx.com/SECURITY_FEATURES/).
- **Homepage** v2.8.0 (2026-11-11): [README](https://github.com/gethomepage/homepage),
  [Documentation](https://gethomepage.dev/),
  [Kubernetes](https://gethomepage.dev/configs/kubernetes/).

These projects move quickly. If something here is out of date, please
[open an issue](https://github.com/gvart/hearth/issues).
