---
title: Guardrails
description: Allow, confirm or deny each class of action, approvals, device ceilings and dry runs.
---

Every action, from the CLI, the web UI or an automation, goes through the hub's policy and lands in
the audit log. Three guardrails sit on top of the built-in action table:

- a per-class **policy file**: allow, hold for approval (`confirm`), or deny;
- the device's **capability ceiling**, which the hub can never raise;
- a **dry run** for every action.

## Policy file

`<data-dir>/policy.yaml` on the hub host. The hub reads it at start; CLI commands on the hub host
read it on every run. Without it, every action the table allows is allowed, except dangerous actions
of automations, which are denied unless granted.

```yaml
classes:                 # for every operator client: admin (CLI), web (UI), automation
  read: allow
  safe: allow
  dangerous: confirm     # allow | confirm | deny
actors:                  # overrides per actor kind
  automation:
    dangerous: deny
  web:
    safe: confirm
dangerous_automations:   # automations allowed dangerous actions without approval
  - disk-report
approval_timeout: 10m    # how long a held action waits; then it is denied (default 10m)
```

The most specific setting wins: a grant in `dangerous_automations` (or `hearth hub
--allow-dangerous-automation <id>`, added to the file's list), then `actors`, then `classes`, then
the defaults. Unknown keys, classes, modes or actor kinds are errors: the hub refuses to start.

Some actions are never held or denied by the file: logging in, enrolling a device, joining and
promoting hubs (each proves itself with a credential, mid-protocol), setting the admin password (the
way back in), and approving or denying an approval itself.

In a cluster the file is per hub, not replicated: keep it the same on every hub.

## Approvals

A `confirm` action is held as a pending approval and the requester waits: the CLI command, the API
request or the automation run. The hold and its outcome are both in the audit log.

```sh
hearth approval list [--all]
hearth approval approve <id>      # the held action runs at once
hearth approval deny <id>
```

The web API has `GET /api/v1/approvals[?status=all]` and `POST /api/v1/approvals/{id}/approve` (or
`/deny`). An approval nobody decides within `approval_timeout` expires and the action is denied; so
is one whose requester gives up (Ctrl-C). A decided or expired approval cannot be decided again.

After a rolling upgrade, nothing can be held until `hearth cluster migrate` brings the cluster to
schema 9: until then `confirm` actions are denied.

## Device capability ceiling

An agent runs only what its own flags allow (`--allow-exec`, `--allow-restart`, see
[automations.md](automations.md)) and reports that ceiling to the hub with its facts. The hub
denies an action beyond the reported ceiling in policy, before it could be held for approval, and
never sends it; the agent checks again before running anything. Agents older than this release
report no ceiling, and the hub sends them no actions until they are upgraded.

## Dry runs

- CLI: `--dry-run` on `token create`, `device revoke` and the `cluster` commands that change
  something. The decision is audited with the result `dry-run` and printed; nothing is done.
- API: `POST /api/v1/tokens` with `"dry_run": true` answers `{"dry_run": true, "decision": ...}`.
- Kubernetes actions: `"dry_run": true` plans the action (see [kubernetes.md](kubernetes.md)) and
  audits the decision as a dry run.
- Automations: `hearth hub --automations-dry-run` audits every action's decision and runs none;
  `hearth automation plan <file>` checks a file without touching policy.
