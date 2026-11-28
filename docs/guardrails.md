---
title: Guardrails
description: Allow, confirm or deny each class of action, approvals, device ceilings and dry runs.
---

Every action, from the CLI, the web UI, an automation or an MCP client, goes through the hub's policy and lands in
the audit log. Three guardrails sit on top of the built-in action table:

- a per-class **policy file**: allow, hold for approval (`confirm`), or deny;
- the device's **capability ceiling**, which the agent enforces itself;
- a **dry run** for every action.

## Policy file

`policy.yaml`, a document of the hub's store (see [Configuration documents](#configuration-documents)):
every hub applies a new one within seconds, without a restart, and CLI commands on a hub host read it
on every run. Without it, every action the table allows is allowed, except dangerous actions
of automations, which are denied unless granted, and dangerous actions of MCP clients, which are held
for approval ([mcp.md](mcp.md)). The holder of a panel's share link is the actor `guest`
([panels.md](panels.md)): it may only take the read and safe actions a panel allows, and setting
`actors: {guest: {safe: confirm}}` holds each of them for approval. A file that sets
`actors.guest.dangerous` to anything but `deny` fails to load. A dashboard such as Homepage is
the actor `dashboard` ([homepage.md](homepage.md)): its token reads the dashboard summary
(`dashboard.read`, class `read`) and nothing else, and `actors: {dashboard: {read: deny}}` turns
dashboards off.

```yaml
classes:                 # for every operator client: admin (CLI), web (UI), automation, mcp, guest, dashboard
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
time, and the same per-address rate limit, which approving and logging in share: a burst of 5
attempts, then one every 12 s (`429` past it). Only a wrong password used to approve counts against
it, so approving many actions in a row is never limited. A refused approval
stays pending and is in the audit log as a denied `approval.approve` whose result says the approver
was not re-authenticated. The password itself is never logged, audited, stored or echoed in a
response.

Every decision is in the audit log as `approval.approve` or `approval.deny`, by who and how: the
actor kind says the channel (`admin` for the CLI, `web` for the UI, `approval_link` for a link) and
the id says who (the local user, or the remote address). The approval records it as `decided_by`.

An approval whose requester is gone, because the hub stopped or crashed while it waited, would stay
pending for good. The hub (in a cluster, the master that owns the approval's sweep on the master
ring) expires every pending
approval more than 5 minutes past its expiry at startup and then every minute, through the same
replicated write as any expiry: its plan is cleared and the denial is in the audit log (written just
before the expiry, so a crash between the two never leaves an unaudited expiry; an approval its own
requester closes at the same moment can leave one extra entry). A sweep that fails, for example
with too few replicas reachable, is logged and tried again a minute later; it never delays startup.

The 5 minutes of grace keep a sweep from expiring a live hold when the sweeping master's clock is
ahead of the hub that holds it. Keep the hubs' clocks within it: a master whose clock runs more than
5 minutes ahead can still expire a hold before its timeout.

### Where a plan survives

The plan of a held request, which can quote command arguments, is removed from the approval row when
it is decided or expires. Copies outside the row stay for a while:

- In a cluster, every replica of the approval row holds the plan until the decision reaches it, and
  a hint kept for a replica that was down (`hints.db`) holds it until it is delivered.
- SQLite has `secure_delete` on, so the pages the plan is removed from are overwritten with zeros
  rather than left in the file's free pages. The write-ahead log (`-wal`) can hold an older copy of
  a page: Hearth sets `journal_size_limit` to 0, so once a checkpoint has copied the frames and the
  next write restarts the log, the file is truncated. A test shows this for an idle store; a
  long-lived reader can hold the log open, and copies remain until the frames are overwritten or the
  store is closed.
- Backups and snapshots of the data directory taken while the approval was pending keep the plan.

Treat the data directory as holding secrets: keep it readable by the hub's user only.

## Configuration documents

`policy.yaml`, `notify.yaml`, every automation file and every runbook file are documents of the hub's
store, the same on every hub of a cluster. Files on disk are import and export only:

```sh
hearth config import /etc/hearth/config      # policy.yaml, notify.yaml, automations/, runbooks/
hearth config import ./policy.yaml           # or one file; --kind for a name it cannot tell
hearth config import --dry-run ./policy.yaml # validate and audit the decision; write nothing
hearth config export ./backup-of-config      # every document, as files (0600)
hearth config delete automation backup.yaml  # an automation or runbook document
```

Run them on a hub host, as the hub's user: they open the data dir directly, like `hearth admin
set-password`. An import adds or replaces the documents it holds and leaves the others. It first
validates the whole configuration it would leave: the policy, the notification channels, the policy's
approval channel, and every automation and runbook as the hub loads them (notify actions against the
imported channels). Anything invalid refuses the whole import and writes nothing, so a configuration is
never half applied. Every hub then applies the documents within seconds; a stored configuration whose
policy or notify document does not parse is not applied, and the hub keeps the one in effect.

The web UI edits the same documents, with the same checks: **Settings → Policy** shows the policy to
anyone signed in and edits it, **Notifications** adds, edits and deletes channels, and **Runbooks** creates,
edits and deletes runbook files, each with a check (and a plan, for a runbook) before saving. An
automation can be deleted from its editor. Each save is `config.import` by `web`; saving the policy or
a channel also asks for the admin password again (see
[security](security.md#sensitive-actions-ask-for-the-password-again)).

| Action               | Class       | Actor                                                   |
| -------------------- | ----------- | ------------------------------------------------------- |
| `config.import`      | `dangerous` | `admin` (an import or a delete), `web` (an editor)      |
| `config.export`      | `read`      | `admin`                                                 |
| `config.import.first`| `dangerous` | `hub`, fixed: a hub's one-time import of its own files  |

`config.import` follows the modes, so `classes: {dangerous: confirm}` holds every import for approval.
An import of a policy that would deny `config.import` to `admin` is refused: nothing could change the
policy back. A policy saved from the web editor is also refused if it would deny `config.import` to
`web`, as the editor could then never change it back; hold dangerous web actions for approval
(`confirm`) instead, or import that policy with `hearth config import` on a hub host. A policy import
is the most powerful change there is, since it decides every other action.

`notify.yaml` holds credentials: it is sealed (AES-256-GCM, with a key derived from the hub CA key)
before it enters the store, so the database, the replication log and snapshots hold ciphertext only. It
is never logged, and no API returns it; the audit entry of an import names documents, never content.
`hearth config export` writes it in clear, mode 0600, on the hub host only. The web editor of channels
is write-only: it says whether each field is set, and an empty field keeps the stored value.

On its first start at schema 28, a hub imports its files once: `<data-dir>/policy.yaml`,
`notify.yaml` (or `--notify-config`), `automations/` (or `--automations-dir`) and `runbooks/` (or
`--runbooks-dir`), audited as `config.import.first`. After that the hub reads only the store and logs
once that the files are import/export only. In a cluster, the first hub to import wins, and the others
take its documents. `--allow-dangerous-automation` is not a document: it stays a flag of each host, a
grant on that host only, added to the policy's `dangerous_automations` there.

### Approve from your phone

With a notification channel (see [notifications.md](notifications.md)), the hub sends every action
it holds to your phone:

```yaml
approval_notify:
  channel: phone                  # a channel of notify.yaml; an import without it is refused
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

The notification is sent by the hub that holds the action (for an automation, the master running
it). Actions held by a CLI command are not notified: their operator is at the terminal. A failed send is logged; the
approval waits as it would anyway.

## Device capability ceiling

An agent runs only what its capability ceiling allows, and nothing by default. The ceiling has two
parts, and the agent uses both:

- **Set on the hub.** Open the device and use its **Capabilities** card, or the CLI on a hub host:

  ```sh
  hearth device capabilities <device-id>               # what is on, and where it is set
  hearth device capabilities <device-id> --set logs=on --set docker=read
  hearth device capabilities <device-id> --set restart=docker:jellyfin,systemd:pihole-FTL.service
  hearth device capabilities <device-id> --set exec=/usr/bin/df --set shell=on
  hearth device capabilities <device-id> --set shell=off
  hearth device capabilities <device-id> --set plugins=go-lamp:safe
  hearth device capabilities <device-id> --set vip=eth0=192.168.1.53/24
  ```

  Each capability is on or off. On is all of it (every log source, every service, the private IPv4
  ranges for a scan); **Restrict to…** names only some, and a name may be a glob (`docker:*`,
  `systemd:pihole-*`). Programs have no "all": each is an absolute path, run with any arguments.
  Virtual IPs have none either: each is `interface=address/prefix`, matched exactly (see
  [Self-heal Pi-hole](automations.md#self-heal-pi-hole); Linux only).
  Containers are off, **read** (list them and read their logs) or **control** (start, stop and
  restart too). The agent applies a change at once, with no restart: it saves it to
  `<data-dir>/ceiling.json` (0600), reports its new facts, and ends a terminal or a log stream it no
  longer allows.
- **Set on the device.** The agent's own flags (`--allow-exec`, `--allow-restart`, `--allow-probe`,
  `--allow-logs`, `--allow-shell`, `--allow-scan`, `--allow-net-edges`, `--allow-docker`,
  `--allow-plugin`, `--allow-vip`, see
  [automations.md](automations.md)) add to what the hub sets. The card shows them as **set on the
  device**: the hub cannot take them away.

Changing it is the policy action `device.capabilities.set` (`safe`: lowering anything, and raising
logs, checks, a scan, neighbours or reading containers) or `device.capabilities.raise` (`dangerous`:
raising a terminal, programs, restarts, container control, a virtual IP or a [plugin](plugins.md#plugins-on-devices),
which also asks for the admin password again). Only an admin, from the web UI or a hub host, may take either; every change is audited,
refusals too. The agent checks each ceiling the hub sends (absolute program paths, valid globs and
subnets) and refuses a bad one whole.

Install a device with `--local-ceiling` (`install.sh --local-ceiling`, or `hearth agent run
--local-ceiling`) and its agent ignores what the hub sets: its flags are its whole ceiling, and its
card is read-only. Use it where nothing on the hub should ever raise what the device allows; the
[Talos DaemonSet](talos.md) runs this way.

The agent reports its ceiling to the hub with its facts. The hub denies an action beyond the
reported ceiling in policy, before it could be held for approval, and never sends it; the agent
checks again before running anything. Agents older than this release take no ceiling from the hub:
their card asks to upgrade them first.

## Dry runs

- CLI: `--dry-run` on `token create`, `device revoke`, `device capabilities --set`, `plugin upload|delete`, `mcp token create|revoke` and the `cluster`
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
| `started` (**No outcome recorded** in the web UI) | The action is still running, the hub stopped before it could report the result, or a cluster lost the replicas for the entry while writing it and the action was refused. It may also have run, with the write of its result failing. Check the target. |
| `read allowed` | A read was allowed to run. Reads record a result only when they fail, so that frequent reads do not write twice. This row does not prove the read succeeded: a read interrupted by a hub crash, or one that failed while its result could not be written, looks the same. |

`GET /api/v1/audit` serves the same data. It takes the query parameters `actor_kind`, `actor`
(part of the actor id), `action`, `class` (`read` / `safe` / `dangerous`), `decision`, `device` (a
device id; matches entries that target its id, name or hostname), `since` and `until` (RFC 3339),
and `limit` (1-500, default 100). A page answers `{"entries": [...], "next_before": <id>,
"actions": [...]}`; pass `before=<next_before>` for the next, older page.
