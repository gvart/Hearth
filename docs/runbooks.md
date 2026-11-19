---
title: Runbooks
description: Multi-step procedures with checks, prompts, retry and rollback.
---

A runbook is a procedure a person starts and follows: a list of steps that act, check the result, ask
a question or wait. When a step fails the run stops, and you choose to retry the step or roll back
what the run already did.

An [automation](automations.md) reacts to an event and runs by itself. A runbook is started by someone
signed in, and keeps its place across hub restarts until someone finishes it.

Runbooks are YAML files in the hub's runbooks directory: `<data-dir>/runbooks` by default, or
`hearth hub --runbooks-dir DIR`. Every `*.yaml` and `*.yml` file in it (not in subdirectories) is one
runbook. A file is read when it is listed, planned or started, so an edit needs no restart.

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
- **check** takes an `http`, `tcp` or `dns` check as in the automation reference. It runs from the hub
  (`from` is not supported), and is tried every `every` until it passes or `within` has passed.
- **prompt** is `input` for a line of text or `confirm` for yes or no. Answering no fails the step.
  `timeout` is 1 hour by default and at most 7 days. A prompt nobody answers in time fails the step.
- **wait** keeps its deadline across a hub restart.

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

Completed steps are never repeated after a restart or a leader change. A wait or a prompt carries on
where it was.

## Prompts and their answers

An answer is data. It can fill in text with `{{ .Input.<step id> }}`, and it can never choose what runs:

| Where                                 | Answers it can use |
| ------------------------------------- | ------------------ |
| webhook `body` and header values      | all, also secret   |
| log `message`, notify text            | not secret         |
| anything else, such as a device, a cluster or an object name | none |

The webhook `url`, `command` and `service` are not templates at all. A runbook that uses an answer
where it may not is rejected when it is loaded.

Mark a prompt `secret: true` for a password or a token. A secret answer is held only in the memory of
the hub running the steps. It is never stored, replicated, logged or shown in the run log. So:

- After a hub restart or a leader change, the run asks for the secret again before any later step whose
  templates use `.Input` in any form, even one that never reads that secret.
- In a cluster, send a secret answer to the leading hub. Other hubs refuse it and name the leader.

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

## A run keeps its definition

A run keeps a sealed copy of the runbook file it started from. Editing or deleting the file changes
later runs only, so a run in progress can always finish or roll back as it was planned.

The hub keeps the newest 100 finished runs, and every unfinished one.

## In a cluster

Run state is replicated through the store like other hub state, so any hub can show a run or take an
operator's decision, and the leader runs the steps. Give every hub the same runbook files.

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
