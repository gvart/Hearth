---
title: Concepts
description: The hub, agents, devices, policy and the audit log, and how they fit together.
---

Hearth applies the Home Assistant model to compute: every machine in your lab becomes an entity you
can see, control and automate from one place. Five ideas carry the whole system.

```
browser, CLI ──► hub ── policy ── automations ── integrations (Prometheus, Kubernetes)
                  ▲        │
                  │        └── audit log (in the hub database)
   agents dial out (mutual TLS, one long-lived stream each)
```

## Hub

The hub is the control plane: `hearth hub`. It keeps all state in one SQLite database in its data dir
(by default `~/.local/share/hearth/hub`, or `/var/lib/hearth/hub` when run as root), together with its
own certificate authority (`ca.crt`, `ca.key`). It serves:

| Port | Serves                                                                                  |
| ---- | --------------------------------------------------------------------------------------- |
| 7443 | agent connections (mutual TLS), and the web UI and JSON API over HTTPS                  |
| 7080 | the web UI and API over plain HTTP, the agent installer `/install.sh` and `/ca.crt`     |

The web UI is built into the binary. It has one account, the admin, whose password you set with
`HEARTH_ADMIN_PASSWORD` on the first start or with `hearth admin set-password`. CLI commands such as
`hearth token create` run on the hub host and work on its data dir directly.

Any machine can be the hub: a Pi, a NAS, a VM, a laptop. Three hubs can form a cluster that survives
the loss of one; see [Cluster mode](cluster.md).

## Agents

An agent is the same `hearth` binary running `hearth agent run` on a device. It always dials out to
the hub, so devices open no ports. It keeps one stream to the hub over mutual TLS and over it:

- reports host facts when it connects: hostname, OS, architecture, kernel, CPU, memory, disks and
  network interfaces;
- sends a heartbeat every 10 seconds;
- reconnects with backoff when the hub goes away, and in a cluster tries the other hubs;
- runs the restarts and commands the hub asks for, but only those its own flags allow (see
  [the device's ceiling](#the-devices-ceiling)).

An agent is small: it is meant to idle under 20 MB of memory and near-zero CPU.

## Devices and enrollment

A device is a machine the hub knows, identified by a device id. It becomes one by **enrolling**:

1. You create an **enrollment token** on the hub, in the UI (**Add device**) or with
   `hearth token create`. A token is single use, expires (15 minutes by default) and is stored only
   as a hash. It also carries the fingerprint of the hub CA.
2. On the device, `hearth agent join https://<hub>:7443` (or the installer, which runs it) checks
   the hub's certificate against that fingerprint *before* sending the token, creates a private key
   that never leaves the device, and sends a certificate request.
3. The hub checks the token, burns it, and signs a one-year client certificate for the device. The
   agent keeps its key, certificate and the hub CA in its data dir.

From then on the device is **online** while its agent is connected and **offline** when the hub has
not heard from it for 30 seconds. `hearth device revoke <device-id>` revokes its certificates: the
agent is disconnected and can never reconnect with them.

## Policy

Every action, whoever asks for it, passes through one policy engine before anything happens:
creating a token, enrolling, logging in, revoking a device, a Kubernetes restart, an automation's
webhook or command on a device. Policy is **deny by default**: an action that is not in its table is
refused.

Each action has a **class**:

| Class       | Meaning                                                      | Examples                                         |
| ----------- | ------------------------------------------------------------ | ------------------------------------------------ |
| `read`      | changes nothing                                              | an automation's `log`, reading pod logs          |
| `safe`      | bounded and repeatable; the routine fix                      | restarting a service, scaling a workload, a webhook |
| `dangerous` | can do anything, or cannot be undone                         | running a command, draining a node, revoking a device |

and a list of **actors** allowed to take it: the local admin on the CLI, a logged-in web session, an
automation, an agent with an enrollment token, another hub. An automation can take a dangerous action
only when the hub grants it by name (`--allow-dangerous-automation <id>`). On top of that table, the
hub's `policy.yaml` can allow, deny or hold for approval (`confirm`) each class, per actor kind, and
every action can be dry-run: see [Guardrails](guardrails.md).

### The device's ceiling

Policy is decided on the hub, but a device has the last word on what runs on it. An agent runs only
the commands and services its own `--allow-exec` and `--allow-restart` flags name, and nothing by
default. The hub can never raise that ceiling: the agent reports it, the hub refuses anything beyond
it before sending, and the agent checks again before running.

## Audit log

Every policy decision, allowed or denied, is written to the audit log in the hub database: who
(actor), what (action and target), when, and the decision, with details that never include secrets.
In a cluster the audit entry is replicated like any other write, in order with the action it records.
The web UI's **Audit** page lists it with filters (time, actor, action, class, decision, device); see
[Guardrails](guardrails.md#audit-log).

## Automations and integrations

**Automations** are YAML files in the hub's automations directory: a trigger (a device goes offline,
a check fails, a metric runs hot, a schedule) starts actions (restart a service, run a command, send
a notification, call a webhook). They act through the same policy and audit log as everything else. See the
[automation reference](automations.md).

**Integrations** bring in what you already run instead of replacing it: device charts and metric
triggers from [Prometheus](prometheus.md), and nodes, workloads and day-two actions from
[Kubernetes](kubernetes.md).
