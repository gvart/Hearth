---
title: MCP (AI assistants)
description: Let Claude Code or another MCP client see and operate the homelab, through policy and the audit log.
---

The hub is a [Model Context Protocol](https://modelcontextprotocol.io) server. An AI assistant such
as Claude Code can list your devices, read their facts, metrics and pod logs, restart a service, run
a command or write an automation, with the same guardrails as every other client: each tool call is
decided by the hub's [policy](guardrails.md) and lands in the audit log, as `mcp/<token name>`.

## Tokens

Each MCP client gets its own token. Create one on the hub host:

```sh
hearth mcp token create claude              # scope safe (the default)
hearth mcp token create ops --scope dangerous
hearth mcp token list
hearth mcp token revoke claude              # refused from its next request
```

The token is printed once; the hub stores only its SHA-256 hash. Its name identifies the client in
policy and the audit log, and is never reused, even after a revocation.

A token's **scope** is the highest class of action it may request, whatever the policy file allows:

| Scope       | The client may                                                                 |
| ----------- | ------------------------------------------------------------------------------ |
| `read`      | list and read devices, metrics, Kubernetes objects and pod logs; plan automations |
| `safe`      | also restart services and act on Kubernetes (restart, scale, delete a pod, cordon) |
| `dangerous` | also run commands, drain nodes and apply automations                           |

A client is only offered the tools its scope allows. A request beyond the scope is denied and
audited.

## Connecting Claude Code

Over stdio, with `hearth mcp` bridging to the hub (any machine with the `hearth` binary):

```sh
claude mcp add hearth --env HEARTH_MCP_TOKEN=hearth_mcp_... -- hearth mcp --hub http://hub.lan:7080
```

Or straight to the hub's streamable HTTP endpoint, `/mcp` on the web port:

```sh
claude mcp add --transport http hearth http://hub.lan:7080/mcp \
  --header "Authorization: Bearer hearth_mcp_..."
```

Over plain HTTP the token crosses the LAN in the clear, as the web session does. Prefer
`https://hub.lan:7443/mcp` (see [https.md](https.md)); `hearth mcp --hub https://hub.lan:7443
--ca-file ca.crt` trusts the hub's CA from `http://hub.lan:7080/ca.crt`.

## Tools

| Tool                | Class        | Policy action                              |
| ------------------- | ------------ | ------------------------------------------ |
| `list_devices`      | read         | `device.read`                              |
| `get_device`        | read         | `device.read`                              |
| `device_metrics`    | read         | `device.metrics`                           |
| `list_kube_objects` | read         | `kube.read`                                |
| `pod_logs`          | read         | `kube.pod.logs`                            |
| `plan_automation`   | read         | `automation.plan`                          |
| `restart_service`   | safe         | `device.restart`                           |
| `kube_action`       | safe or dangerous | `kube.workload.*`, `kube.pod.delete`, `kube.node.*` (drain is dangerous) |
| `exec_command`      | dangerous    | `device.exec`                              |
| `apply_automation`  | dangerous    | `automation.apply`                         |

`restart_service` and `exec_command` reach the device through its agent, within the agent's own
ceiling (`--allow-restart`, `--allow-exec`, see [automations.md](automations.md)): a service or
program the agent does not allow is denied before anything is sent. `exec_command` answers with the
exit code, not the output. The command it runs is in the approval and the audit log, so the
operator sees what they approve: keep secrets out of commands.

`apply_automation` writes `<id>.yaml` to the hub's automations directory, which the hub then loads;
its plan is in the approval, and the audit log names only the file. Every action also takes `dry_run`: the decision is
audited, and nothing runs.

## Approvals

With no policy file, a dangerous MCP request is held for approval: the tool call waits, for up to
`approval_timeout` (10 minutes by default), until an operator decides on the hub host or in the web
UI. The held request shows as `mcp/<token name>`:

```sh
hearth approval list
hearth approval approve <id>      # the held action runs, and the tool call returns
```

The policy file sets it like any other actor kind ([guardrails.md](guardrails.md)):

```yaml
actors:
  mcp:
    safe: confirm       # hold restarts too
    dangerous: deny     # never run commands from an assistant
```

`classes` applies to MCP clients too: `classes: {dangerous: allow}` lets them run dangerous actions
without approval, unless `actors.mcp` says otherwise.

## In a cluster

The MCP endpoint is on every hub, but only the leader has the agents' streams: point clients at
the leader (or at an address that follows it) to restart services or run commands. Automations
written by `apply_automation` go to that hub's automations directory, which is not replicated.
