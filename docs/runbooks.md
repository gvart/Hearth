---
title: Runbooks
description: Multi-step procedures with checks, prompts, retry and rollback.
---

A runbook is a procedure a person starts and follows: a list of steps that act, check the result, ask
a question or wait. When a step fails the run stops, and you choose to retry the step or roll back
what the run already did.

An [automation](automations.md) reacts to an event and runs by itself. A runbook is started by someone
signed in, and keeps its place across hub restarts until someone finishes it.

Runbooks are YAML files held in the hub's store, the same on every hub of a cluster, imported with
`hearth config import DIR` from `DIR/runbooks` (see [guardrails](guardrails.md#configuration-documents));
on its first start a hub imports its `<data-dir>/runbooks` directory (or `--runbooks-dir`) once. Every
`*.yaml` and `*.yml` file (not in subdirectories) is one runbook. A runbook is read when it is listed,
planned or started, so an import needs no restart.

The web UI's **Runbooks** page also creates, edits and deletes them: **New runbook**, or **Edit** on a
runbook, opens the file as YAML. **Check and plan** validates it and shows its plan (each step, and the
policy decision for those that act) without running anything; **Save…** checks it again and asks before
saving. A new runbook is saved as `<id>.yaml`. Saving and deleting are `config.import` by `web`,
decided by policy and audited, like an import.

## A worked example

This runbook upgrades an app behind a load balancer. It asks for a go-ahead and a reason, takes the
app out of rotation, deploys, waits, and checks that the app is healthy.

```yaml
id: upgrade-app            # lowercase letters, digits, - and _; unique across files
description: Upgrade the app behind the load balancer.
steps:
  - id: go-ahead
    type: prompt
    prompt: confirm
    message: Upgrade the app now?
    timeout: 15m

  - id: reason
    type: prompt
    prompt: input
    message: Why is this upgrade happening?

  - id: drain
    type: action
    description: Take the app out of rotation.
    action:
      type: webhook
      url: http://lb.lan:8080/drain
      body: 'reason={{ .Input.reason }}'
    rollback:
      type: webhook
      url: http://lb.lan:8080/undrain

  - id: settle
    type: wait
    duration: 30s

  - id: deploy
    type: action
    action:
      type: webhook
      url: http://deploy.lan:8080/upgrade
    rollback:
      type: webhook
      url: http://deploy.lan:8080/downgrade

  - id: healthy
    type: check
    check:
      type: http
      url: http://app.lan:8080/health
      status: 200
    within: 2m
    every: 5s
```

Ready-to-copy runbooks for adding a Talos node, a k3s node or a Docker host are in
[Runbook recipes](runbook-recipes.md).

See what it would do, then start it:

```sh
hearth runbook plan upgrade-app
hearth runbook start upgrade-app
```

Suppose `deploy` fails. The run stops there, and the Runbooks page offers **Retry step** and
**Roll back**. Retrying runs `deploy` again. Rolling back runs the rollback of `drain`; `deploy` itself
failed, so its rollback does not run.

## Steps

Every step has an `id`, unique in the file, a `type`, and optionally a `description`. A runbook has at
most 100 steps, in a file of at most 64 KiB.

| Type     | Fields                                                  | Done when                         |
| -------- | ------------------------------------------------------- | --------------------------------- |
| `action` | `action`, optional `rollback`                           | the action succeeds               |
| `check`  | `check`, optional `within`, `every`                     | the check passes                  |
| `prompt` | `prompt`, `message`, optional `secret`, `timeout`       | someone answers                   |
| `wait`   | `duration` (at most 24h)                                | the time has passed               |

- **action** takes any action of the [automation reference](automations.md), with the same fields.
  `rollback` is another action, which undoes this one.
- **check** takes an `http`, `tcp` or `dns` check as in the automation reference, or a `kube_node`
  or `talos_node` check, and is tried every `every` until it passes or `within` has passed. It runs
  from the hub unless it sets `from`; see [Checks from a device](#checks-from-a-device).
- **prompt** is `input` for a line of text or `confirm` for yes or no. Answering no fails the step.
  `timeout` is 1 hour by default and at most 7 days. A prompt nobody answers in time fails the step.
- **wait** keeps its deadline across a hub restart.

### Checks from a device

A check with `from` (a device id, name or hostname) runs on that device's agent, to verify something
only reachable from inside the device's network or on its localhost:

```yaml
  - id: db-reachable
    type: check
    check: {type: tcp, address: 10.20.0.5:5432, from: pi5, timeout: 5s}
    within: 1m
    every: 5s
```

- The device's agent must allow it: `hearth agent run --allow-probe`, as for an
  [automation check from a device](automations.md). The hub never sends a check beyond the ceiling
  the agent reports, and the agent refuses it again.
- `timeout` is at most 1m.
- Each attempt at the step is decided as `automation.probe` (class `read`) on the device, with one
  audit entry, however often it polls within `within`. A retry is a new decision.
- A policy denial, or an agent that is too old or whose ceiling does not allow probes, marks the step
  `denied`; plan mode shows that denial too. An unknown device, or an agent that is offline, fails the
  step at once, without waiting for `within`.
  The check never falls back to running from the hub. Retry or roll back as for any failed step.

### A Kubernetes node is Ready

A `kube_node` check passes when the Node is Ready, read by the hub from a cluster it has
[adopted](kubernetes.md), named as on the Kubernetes page:

```yaml
  - id: node-ready
    type: check
    check: {type: kube_node, cluster: homelab, node: pi-3}
    within: 15m
    every: 15s
```

- Each attempt at the step is decided as `kube.node.ready` (class `read`) on `<cluster>/<node>`, with
  one audit entry, however often it polls. The hub reads the Node through the cluster's kubeconfig.
- A node that is not there yet fails the check like one that is not Ready, so the step keeps trying
  while a new node registers. A cluster the hub has not adopted fails the step at once.
- It always runs from the hub: it has no `from`.

To remove a Node object, such as the one a node leaves behind after a rollback, use the
`kube_node_delete` action (`kube.node.delete`, dangerous) from the
[automation reference](automations.md#kubernetes-actions).

### A Talos node runs a version

A `talos_node` check reads a Talos node through the Talos API, with the hub's
[talosconfig](talos.md). It passes when the node answers, runs `version` if set, and has every service
healthy if `healthy: true` is set:

```yaml
  - id: upgraded
    type: check
    check: {type: talos_node, node: 192.0.2.50, version: v1.12.8, healthy: true}
    within: 20m
    every: 15s
```

- `node` is the node's address as the talosconfig context (or `--talos-nodes`) names it, or its
  hostname. A node that is down has no hostname to match, so name it by address in a check that waits
  for a reboot.
- `version` is the Talos version tag; `v1.12.8` and `1.12.8` are the same. Without it, any version
  passes.
- `healthy: true` needs every service Running (or Finished) and none failing its health check. It is
  stricter than the [From Talos](talos.md) table: apid, containerd, cri, etcd, kubelet and trustd must
  have passed their health check, as they may run with their health still unknown right after a
  reboot. The error names the services that are not healthy.
- Each attempt at the step is decided as `talos.read` (class `read`) on the node, with one audit entry,
  however often it polls. The hub reads every node of its talosconfig on each poll, with the same
  read-only client as its own reads.
- A node that cannot be read, a version that does not match, an unhealthy service, a node not among
  those read, and a Talos API that does not answer at all fail the check, so the step keeps trying
  while the node reboots. A hub started without `--talosconfig` fails the step at once.
- It always runs from the hub: it has no `from`.

## Vars

A runbook can name the values its steps repeat, such as a device, an address or a node, once in a
`vars` block, and use them in any step as `${{ vars.<name> }}`:

```yaml
id: add-node
vars:
  device: talos-new
  node-ip: 192.0.2.50
steps:
  - id: api
    type: check
    check: {type: tcp, address: "${{ vars.node-ip }}:50000"}
    within: 10m
  - id: apply
    type: action
    action:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/local/bin/talosctl, apply-config, --nodes, "${{ vars.node-ip }}"]
```

- Vars are filled in when the file is loaded, from the file only. The plan shows every step with its
  values filled in. A var is used as written, so keep secrets out of vars, as out of the rest of the
  file.
- A var's value is a literal: it cannot hold a template (`{{ ... }}`) or another var. A prompt answer can
  never set a var, so a var can name a device, an address or a command where an answer cannot.
- A step that uses a var that is not declared, and a var that no step uses, are load errors, as is any
  other `${{ ... }}`.
- Var names are lowercase letters, digits, `-` and `_`. Field names are not filled in, only values.
- Quote a value that starts with `${{` inside `[...]` or `{...}`, such as `["${{ vars.node-ip }}"]`:
  YAML reads an unquoted `{` there as the start of a mapping.

## Plan mode

`hearth runbook plan <id>`, or **Plan** on the Runbooks page, lists every step and rollback step with
the policy decision it would get now: allow, confirm or deny. A plan executes nothing.

## When a step fails

A run that stops can be continued in two ways:

- **Retry** runs the step it stopped at again, with a new policy decision.
- **Roll back** runs the declared rollback steps of the completed steps, last step first.

If a rollback step fails, the rollback stops too. Retry that rollback step, or pass over it and go on
with the rest (`hearth runbook pass-over <run> <step>`, **Pass over and continue** on the page). The
step named has to be the one the rollback stopped at. Passing over
is its own audited decision: what that step should have undone stays as it is.

Each decision names the version of the run it was made on. A repeated or late request is refused, and
the run is left as it is.

### A step with an unknown outcome

If the hub dies while a step is running, or an action or rollback step times out or loses its
connection before the answer comes, nobody knows whether it happened. The run stops with the status
`unknown`, and Hearth never runs that step again by itself: look at the device, then retry or roll back.
A roll back includes the rollback of the unknown step, as it may have happened. Only a definite refusal
or error from the target, or a first hop that could not be reached at all, makes a step `failed`. A node
drain that stops after cordoning the node, a Kubernetes write that was sent and not answered or that
the API server answered with a timeout, a webhook write (POST, PUT, PATCH or DELETE) answered `504`, and an
action that ran but whose outcome could not be written to the audit log are `unknown` too. An action
refused because its first audit entry could not be written never ran, so it is `failed`.

Each runbook keeps its newest 100 `failed` runs. Runs that are `unknown` or `rollback_failed` are kept until
you resolve them, and a runbook with 100 of those refuses new runs until you do.

Secret answers are dropped from the hub's memory when a run stops, so a retry asks for them again.

Completed steps are never repeated after a restart or when the run moves to another master. A wait or a prompt carries on
where it was.

## Prompts and their answers

An answer is data. It can fill in text with `{{ .Input.<step id> }}`, and it can never choose what runs:

| Where                                 | Answers it can use |
| ------------------------------------- | ------------------ |
| webhook `body` and header values      | all, also secret   |
| log `message`, notify text            | not secret         |
| anything else, such as a device, a cluster or an object name | none |

The webhook `url`, `command` and `service` are not templates at all. A runbook that uses an answer
where it may not is rejected when it is loaded. To name a target once, use a [var](#vars): it comes
from the file, never from an answer.

Mark a prompt `secret: true` for a password or a token. A secret answer is held only in the memory of
the hub running the steps. It is never stored, replicated, logged or shown in the run log. So:

- After a hub restart, or when the run moves to another master, the run asks for the secret again
  before any later step whose templates use `.Input` in any form, even one that never reads that secret.
- In a cluster, send a secret answer to the master running the run. Other masters refuse it (409) and
  name that master.

## Policy and audit

Every action step, rollback and retry gets its own policy decision and audit entry, as a run of an
automation does. The actor is `automation/runbook/<id>`, so a dangerous action needs its own grant:

```sh
hearth hub --allow-dangerous-automation runbook/upgrade-app
```

A grant for an automation with the same id does not apply. A denied step does not run, and the run
stops with the step marked `denied`. `hearth hub --automations-dry-run` also applies to runbooks.

People act through a signed-in session. These actions are audited with who took them:

| Action             | Class | Meaning                 |
| ------------------ | ----- | ----------------------- |
| `runbook.start`    | safe  | start a run             |
| `runbook.answer`   | safe  | answer a prompt         |
| `runbook.retry`    | safe  | retry a stopped step    |
| `runbook.rollback` | safe  | roll a stopped run back |
| `runbook.pass_over` | safe | pass over a stopped rollback step |
| `runbook.check`    | read  | run a check step        |
| `automation.probe` | read  | run a check step `from` a device |
| `kube.node.ready`  | read  | run a `kube_node` check step |
| `plugin.command.*` | the manifest's | run a `plugin_command` action step (see [automations.md](automations.md#plugin-commands)) |
| `talos.read`       | read  | run a `talos_node` check step |

## A run keeps its definition

A run keeps a sealed copy of the runbook file it started from. Editing or deleting the file changes
later runs only, so a run in progress can always finish or roll back as it was planned.

The hub keeps the newest 100 finished runs, and every unfinished one.

## In a cluster

Run state is replicated through the store like other hub state, so any hub can show a run or take an
operator's decision, and the master that owns the run on the master ring runs the steps. Runbook files are documents of the replicated
store, so every hub starts a run from the same file.

## Commands

```sh
hearth runbook list                       # the runbooks on the hub
hearth runbook plan <runbook>             # what a run would do
hearth runbook start <runbook>            # start a run
hearth runbook runs [runbook]             # recent runs
hearth runbook show <run>                 # a run's steps and log
hearth runbook answer <run> <step> [value] # answer a prompt; a secret is only ever asked for, unechoed
hearth runbook retry <run>                # run the stopped step again
hearth runbook rollback <run>             # roll a stopped run back
hearth runbook pass-over <run> <step>     # give up on a stopped rollback step and go on
```

The commands use the hub's API (`--hub-url`, default `http://127.0.0.1:7080`) and sign in with the admin
password, from `HEARTH_ADMIN_PASSWORD` or asked for. Leave the value out of `answer` for a secret, so it
does not end up in your shell history.
