---
title: Web terminal
description: A shell on any device from the browser, behind policy, the agent's ceiling and the audit log.
---

The device drawer's **Terminal** button opens a shell on the device in a new browser tab
(`#/terminal/<device id>`), on a real pseudo-terminal, through the device's agent. Linux and macOS
agents support it; Windows agents refuse it.

## Turning it on

A terminal is off by default, on every device. Start the agent with `--allow-shell`:

```sh
hearth agent run --allow-shell
```

The shell runs as the agent's user, in its home directory: `$SHELL` when it is set, else
`/bin/bash`, else `/bin/sh`, as a login shell (`-l`), with `TERM=xterm-256color` and without the
agent's `HEARTH_*` variables. A terminal can do anything that user can, so `--allow-shell` is the
same as `--allow-exec` of every program: grant it only where an admin may log in anyway.

The flag is part of the device's capability ceiling, which the agent reports to the hub. The hub
refuses a terminal to an agent whose ceiling does not allow it, or that is too old to say (an agent
from before this release: upgrade it), before asking; the agent refuses again whatever the hub says. The issue's
`exec: off | allowlist | full` maps onto the flags: no flags is `off`, `--allow-exec <program>` is
the allowlist, `--allow-shell` is `full`.

## Policy and audit

Opening a terminal is the policy action `device.shell`, class `dangerous`, open only to the web UI
behind an admin session: never to an automation or an MCP client. The policy file decides on it as
on any dangerous web action, so

```yaml
actors:
  web:
    dangerous: confirm
```

holds each terminal for approval (the terminal shows "Waiting for approval" until someone approves
it on the Approvals page or with an approval link), and `deny` refuses it.

Each session leaves two entries in the audit log, both with the action `device.shell` and the
device as the target: one when it opens (who: `web/<address>`, the device's name and the shell),
and one when it ends, with the reason, the exit status and the duration. What goes through the
terminal is never recorded, in the audit log or in any log.

## Limits

| Hub flag                  | Default | What it does                                    |
| ------------------------- | ------- | ----------------------------------------------- |
| `--terminal-idle-timeout` | `15m`   | ends a session nobody typed in for this long    |
| `--terminal-max-duration` | `4h`    | ends any session this long after it opened      |

A session also ends when its tab closes (or loses its connection to the hub), when the admin signs
out or the admin session expires, when the agent's connection to the hub ends, and when the shell
exits. Ending a session hangs up every process of the shell's session (SIGHUP), foreground and
background jobs included, and kills what is left two seconds later. Only a process that left the
session on purpose (`setsid`) survives. Output does not count as activity: a `tail -f` nobody types
in ends at the idle timeout.

The terminal is served by the hub the agent is connected to: in a cluster, the leader. The browser
talks to it over a WebSocket on `/api/v1/devices/{id}/shell`, with the session cookie, and only
from the hub's own pages (the `Origin` must be the hub).
