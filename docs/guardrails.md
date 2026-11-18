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
approval_notify:         # send held actions to your phone (see "Approve from your phone")
  channel: phone
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

The web UI's **Approvals** page lists the pending approvals, each with **Approve** and **Deny**, and
the decided ones below; the nav shows how many are waiting. It refreshes every 5 s.

Every decision is in the audit log as `approval.approve` or `approval.deny`, by who and how: the
actor kind says the channel (`admin` for the CLI, `web` for the UI, `approval_link` for a link) and
the id says who (the local user, or the remote address). The approval records it as `decided_by`.

After a rolling upgrade, nothing can be held until `hearth cluster migrate` brings the cluster to
schema 9: until then `confirm` actions are denied.

### Approve from your phone

With a notification channel (see [notifications.md](notifications.md)), the hub sends every action
it holds to your phone:

```yaml
approval_notify:
  channel: phone                  # a channel of notify.yaml; the hub refuses to start without it
  url: https://hearth.lan:8443    # optional: the web UI as the phone reaches it
                                  # (default https://<first --host>:<port>)
```

The message says who wants what, on which target, and when it expires, with a **Review** link (on
ntfy, a button and a tap on the notification). The link opens a page that shows the action, with
**Approve** and **Deny**: opening it decides nothing, a tap does. It needs no login: the link is
the credential, for that one approval only.

- It is a 256-bit random secret, of which the hub stores only the SHA-256 hash.
- It works once: the first approve or deny spends it, whatever the outcome.
- It expires with the approval (`approval_timeout`, default 10 minutes).
- It is in the URL's `#` fragment, which browsers never send to a server, and the page then sends it
  in a POST body: it is in no server log, path or query string. The hub never logs it or audits it.
- A wrong, used or expired link gets the same answer, and is audited as a denied `approval_link`
  decision.

Anyone who can read the channel can approve, so treat it like a password: a self-hosted ntfy server
or an access-token protected topic, or a private Telegram chat. An ntfy server keeps the message
(with its link) in its cache, but the link is dead after its first use or its approval's expiry.

The notification is sent by the hub that holds the action (the leader, for automations). Actions
held by a CLI command are not notified: their operator is at the terminal. A cluster before schema
10 (`hearth cluster migrate`) sends the notification without a link. A failed send is logged; the
approval waits as it would anyway.

## Device capability ceiling

An agent runs only what its own flags allow (`--allow-exec`, `--allow-restart`, `--allow-probe`, see
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
- Automations: `hearth hub --automations-dry-run` audits every action's decision and runs none
  (Kubernetes actions it would allow are planned, and the plan recorded in the run; triggers still
  watch, so checks `from` a device still run, as they change nothing);
  `hearth automation plan <file>` checks a file without touching policy.

## Audit log

Every decision above lands in the audit log. The web UI's **Audit** page lists it, newest first,
with filters for time range, actor kind and id, action, class, decision and device. Click a row
for its detail (approval id, automation run, step). Dry runs carry a "dry run" tag.

`GET /api/v1/audit` serves the same data. It takes the query parameters `actor_kind`, `actor`
(part of the actor id), `action`, `class` (`read` / `safe` / `dangerous`), `decision`, `device` (a
device id; matches entries that target its id, name or hostname), `since` and `until` (RFC 3339),
and `limit` (1-500, default 100). A page answers `{"entries": [...], "next_before": <id>,
"actions": [...]}`; pass `before=<next_before>` for the next, older page.
