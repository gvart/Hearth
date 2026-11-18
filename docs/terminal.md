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

## HTTPS only

What goes through a terminal includes passwords, so the hub serves terminals only over HTTPS. There
is no flag to turn this off. The hub allows a terminal when the request comes from the hub's own
page (its `Origin` host is the host the browser asked for) and one of these holds:

- the browser reached the hub over TLS;
- the page was loaded over `https://`, as behind a TLS-terminating reverse proxy or `tailscale serve`
  (the proxy must pass the original `Host` header on; `X-Forwarded-*` headers are not read);
- the browser runs on the hub itself: the page is on `localhost`, `127.0.0.1` or `[::1]`, and the
  connection comes from the loopback interface.

Anything else is refused and recorded in the audit log as a denial, a browser on
`http://192.168.x.x:7080` included. On such a page the **Terminal** button is disabled and links to
[HTTPS setup](https.md).

Opening a link to a terminal does not start a shell by itself: only the **Terminal** button does, or
the **Connect** button on the page the link opens.

## What the shell can reach

The shell inherits the agent's user and sandbox. Under the shipped systemd unit
(`deploy/systemd/hearth-agent.service`) that means it runs **as root, inside the unit's sandbox**:

- `/usr`, `/boot` and `/etc` are read-only (`ProtectSystem=full`), and so is `/home`
  (`ProtectHome=read-only`);
- `/tmp` is private to the agent (`PrivateTmp=yes`);
- setuid programs gain no privileges (`NoNewPrivileges=yes`), and none can be created
  (`RestrictSUIDSGID=yes`).

This is read from the unit, not measured on a running service. To administer the device without
these limits, use SSH.

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

At most four terminals can be open on a device at a time. A paste larger than 512 KiB that the shell
cannot keep up with ends the session.

A session also ends when its tab closes (or loses its connection to the hub), when the admin signs
out or the admin session expires, when the agent's connection to the hub ends, and when the shell
exits. Ending a session hangs up every process of the shell's session (SIGHUP), foreground and
background jobs included, and kills what is left two seconds later. When the shell exits by itself,
for example after `exit`, what is left is killed at once, `nohup` jobs included. Only a process that
left the session on purpose (`setsid`) survives. Only typing and pasting count as activity: neither
output, resizing the window nor the terminal's automatic answers to the shell do, so a `tail -f`
nobody types in ends at the idle timeout.

The terminal is served by the hub the agent is connected to: in a cluster, the leader. The browser
talks to it over a WebSocket on `/api/v1/devices/{id}/shell`, with the session cookie.
