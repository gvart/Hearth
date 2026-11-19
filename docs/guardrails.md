---
title: Guardrails
description: Allow, confirm or deny each class of action, approvals, device ceilings and dry runs.
---

Every action, from the CLI, the web UI, an automation or an MCP client, goes through the hub's policy and lands in
the audit log. Three guardrails sit on top of the built-in action table:

- a per-class **policy file**: allow, hold for approval (`confirm`), or deny;
- the device's **capability ceiling**, which the hub can never raise;
- a **dry run** for every action.

## Policy file

`<data-dir>/policy.yaml` on the hub host. The hub reads it at start; CLI commands on the hub host
read it on every run. Without it, every action the table allows is allowed, except dangerous actions
of automations, which are denied unless granted, and dangerous actions of MCP clients, which are held
for approval ([mcp.md](mcp.md)).

```yaml
classes:                 # for every operator client: admin (CLI), web (UI), automation, mcp
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

A grant in `dangerous_automations` follows the automation's id, not the content of its file. Saving a
file from the web UI with a dangerous action that the automation could then run without asking anyone,
by such a grant or an `allow` mode, therefore always waits for approval, whatever the modes say, and is
refused on a hub that cannot hold approvals.

Some actions are never held or denied by the file: logging in, enrolling a device, joining and
promoting hubs (each proves itself with a credential, mid-protocol), setting the admin password (the
way back in), and approving or denying an approval itself.

In a cluster the file is per hub, not replicated: keep it the same on every hub.

## Approvals

A `confirm` action is held as a pending approval and the requester waits: the CLI command, the API
request or the automation run. The hold and its outcome are both in the audit log.

```sh
hearth approval list [--all]
hearth approval approve <id>      # asks for the admin password; the held action runs at once
hearth approval deny <id>
```

The web API has `GET /api/v1/approvals[?status=all]` and `POST /api/v1/approvals/{id}/approve` (or
`/deny`). An approval nobody decides within `approval_timeout` expires and the action is denied; so
is one whose requester gives up (Ctrl-C). A decided or expired approval cannot be decided again.

The web UI's **Approvals** page lists the pending approvals, each with **Approve** and **Deny**, and
the decided ones below; the nav shows how many are waiting. It refreshes every 5 s.

#### Approving asks for the password again

Approving a held action takes the admin password again, at the moment of approval. A session alone
cannot approve: someone holding a stolen session cookie, or the session that asked for the action,
can see and deny a held action but not let it run. This works with a single admin, who just types
the password once more. Denying needs no password: it can only stop an action.

- The web UI asks for the password below the plan, when you press **Approve…**. A wrong password
  says so and leaves the action waiting.
- The API takes it in the body: `POST /api/v1/approvals/{id}/approve` with
  `{"password": "..."}` (`Content-Type: application/json`). A missing or wrong password is answered
  `403` with code `reauth_failed`, not `401`, since the session itself is still valid.
- `hearth approval approve <id>` prompts for it without echo on a terminal, and otherwise reads the
  first line of stdin, for scripts: `hearth approval approve <id> < password-file`. It needs an admin
  password to be set (`hearth admin set-password`).

The password is checked as login checks it: the same argon2id hash and cost, one verification at a
time, and the same per-address rate limit, which approving and logging in share (a burst of 5
guesses, then one every 12 s; `429` past it). A refused approval stays pending and is in the audit
log as a denied `approval.approve` whose result says the approver was not re-authenticated. The
password itself is never logged, audited, stored or echoed in a response.

Every decision is in the audit log as `approval.approve` or `approval.deny`, by who and how: the
actor kind says the channel (`admin` for the CLI, `web` for the UI, `approval_link` for a link) and
the id says who (the local user, or the remote address). The approval records it as `decided_by`.

An approval whose requester is gone, because the hub stopped or crashed while it waited, would stay
pending for good. The hub (in a cluster, its leader, as soon as it leads) expires every pending
approval more than 5 minutes past its expiry at startup and then every minute, through the same
replicated write as any expiry: its plan is cleared and the denial is in the audit log (written just
before the expiry, so a crash between the two never leaves an unaudited expiry; an approval its own
requester closes at the same moment can leave one extra entry). A sweep that fails, for example
without a quorum, is logged and tried again a minute later; it never delays startup.

The 5 minutes of grace keep a sweep from expiring a live hold when the leader's clock is ahead of
the hub that holds it. Keep the hubs' clocks within it: a leader whose clock runs more than 5
minutes ahead can still expire a hold before its timeout.

### Where a plan survives

The plan of a held request, which can quote command arguments, is removed from the approval row when
it is decided or expires. Copies outside the row stay for a while:

- The Raft log entry that created the approval and the retained Raft snapshots hold the plan until
  Raft compacts the log and replaces the snapshots. Hearth cannot scrub them sooner, and every hub
  of a cluster keeps its own copies.
- SQLite has `secure_delete` on, so the pages the plan is removed from are overwritten with zeros
  rather than left in the file's free pages. The write-ahead log (`-wal`) can hold an older copy of
  a page: Hearth sets `journal_size_limit` to 0, so once a checkpoint has copied the frames and the
  next write restarts the log, the file is truncated. A test shows this for an idle store; a
  long-lived reader can hold the log open, and copies remain until the frames are overwritten or the
  store is closed.
- Backups and snapshots of the data directory taken while the approval was pending keep the plan.

Treat the data directory as holding secrets: keep it readable by the hub's user only.

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
**Deny** and **Sign in to approve**: opening it decides nothing, a tap on **Deny** does. Denying
needs no login: the link is the credential, for that one approval only, and only to deny.

A link cannot approve. Approving takes the admin password again (see
[Approving asks for the password again](#approving-asks-for-the-password-again)), so **Sign in to
approve** opens the **Approvals** page, where you sign in and approve with your password. An approve
through the link's API (`POST /api/v1/approval-link/approve`) is refused with `403`
`signin_required`, audited as a denied `approval_link` decision, and leaves the link unspent.

- It is a 256-bit random secret, of which the hub stores only the SHA-256 hash.
- It works once: the first deny spends it, whatever the outcome.
- It expires with the approval (`approval_timeout`, default 10 minutes).
- It is in the URL's `#` fragment, which browsers never send to a server, and the page then sends it
  in a POST body: it is in no server log, path or query string. The hub never logs it or audits it.
- A wrong, used or expired link gets the same answer, and is audited as a denied `approval_link`
  decision.

Anyone who can read the channel can deny, and see what is held, so keep it private: a self-hosted ntfy server
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

- CLI: `--dry-run` on `token create`, `device revoke`, `mcp token create|revoke` and the `cluster`
  commands that change something. The decision is audited with the result `dry-run` and printed; nothing is done.
- API: `POST /api/v1/tokens` with `"dry_run": true` answers `{"dry_run": true, "decision": ...}`.
- Kubernetes actions: `"dry_run": true` plans the action (see [kubernetes.md](kubernetes.md)) and
  audits the decision as a dry run.
- MCP: every action tool takes `dry_run` ([mcp.md](mcp.md)).
- Automations: `hearth hub --automations-dry-run` audits every action's decision and runs none
  (Kubernetes actions it would allow are planned, and the plan recorded in the run; triggers still
  watch, so checks `from` a device still run, as they change nothing);
  `hearth automation plan <file>` checks a file without touching policy. The web UI's automation
  editor has a **Dry run** button: see [automations.md](automations.md#the-visual-editor).

## Audit log

Every decision above lands in the audit log. The web UI's **Audit** page lists it, newest first,
with filters for time range, actor kind and id, action, class, decision and device. Click a row
for its detail (approval id, automation run, step). Dry runs carry a "dry run" tag.

An action is written to the audit log before it runs: if that write fails, the action is refused and
nothing happens. Its result then replaces the entry, so each action is one row:

| Result | Meaning |
| --- | --- |
| `ok` or `error: ...` | The action ran and this is how it ended. |
| `started` (**No outcome recorded** in the web UI) | The action is still running, the hub stopped before it could report the result, or a cluster lost its leader while writing the entry and the action was refused. It may also have run, with the write of its result failing. Check the target. |
| `read allowed` | A read was allowed to run. Reads record a result only when they fail, so that frequent reads do not write twice. This row does not prove the read succeeded: a read interrupted by a hub crash, or one that failed while its result could not be written, looks the same. |

`GET /api/v1/audit` serves the same data. It takes the query parameters `actor_kind`, `actor`
(part of the actor id), `action`, `class` (`read` / `safe` / `dangerous`), `decision`, `device` (a
device id; matches entries that target its id, name or hostname), `since` and `until` (RFC 3339),
and `limit` (1-500, default 100). A page answers `{"entries": [...], "next_before": <id>,
"actions": [...]}`; pass `before=<next_before>` for the next, older page.
