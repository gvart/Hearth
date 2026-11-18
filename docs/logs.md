---
title: Logs
description: Tail journald units, Docker containers and Kubernetes pods from the UI.
---

Debugging starts with logs. Hearth streams them on demand from the device and stores nothing: open a
device in the UI, pick a log under **Logs**, and its last lines appear, followed by new ones as they
are written. Close the view and the device stops reading.

## Allow a log on the device

Logs can hold secrets (tokens in URLs, passwords in a failed command line), so an agent streams
nothing unless its own `--allow-logs` flag names the source. Like `--allow-exec` and
`--allow-restart`, it is the device's [capability ceiling](concepts.md#the-devices-ceiling): nothing
on the hub can raise it.

```sh
hearth agent run \
  --allow-logs systemd:pihole-FTL.service \
  --allow-logs 'docker:*' \
  --allow-logs 'systemd-user:backup-*'
```

Each entry is `manager:name`, where the name may be a glob (`*`, `?`, `[...]`):

| Entry | Streams |
| --- | --- |
| `systemd:UNIT` | `journalctl --unit=UNIT --follow` |
| `systemd-user:UNIT` | `journalctl --user-unit=UNIT --follow`: the agent user's own `systemctl --user` units |
| `docker:CONTAINER` | `docker logs --follow --timestamps CONTAINER`, stdout and stderr |

`systemd:*` does not cover user units, and the agent runs no shell: the name is passed to
`journalctl` or `docker` as one argument. The agent's user needs read access to the journal (root,
or the `systemd-journal` or `adm` group, for system units, and for user units where the journal is
not split per user) and to the Docker socket.

## In the UI

The device drawer lists the allowed sources. An exact entry opens at once; a glob asks for the unit
or container name. The viewer has:

- **Follow**: keep the newest line in view.
- **Pause**: freeze the view while lines keep arriving; **Resume** shows how many came meanwhile.
- **Filter**: show only the lines that contain the text (case-insensitive).
- **Last**: how many past lines to start with (100 or 500).

Kubernetes pod logs (on the [Kubernetes](kubernetes.md) page) open in the same viewer, as a
snapshot of the last lines with **Refresh**, since the Kubernetes API reads them on demand.

## Policy and audit

Opening a stream is the policy action `device.logs`, class `read`, for the web UI. Each stream
opened is one audit entry, with the device and the source; a refused one (beyond the ceiling, or an
agent too old to stream logs) is audited as denied. The hub checks the ceiling the agent reported
before asking, and the agent checks again before it starts `journalctl` or `docker`.

## How it works

- The hub sends a `LogRequest` over the agent's existing stream; the agent answers with batches of
  lines. Agents older than protocol 1.4 cannot stream logs: the UI says the agent is too old.
- Streams of the same source on a device share one `journalctl` or `docker logs` process and a ring
  of its last 500 lines, so a second viewer starts at once. When the last viewer closes, the process
  is stopped and the ring dropped: nothing is kept for a source nobody reads.
- When the browser goes away (tab closed, network lost) the hub tells the agent to stop. A viewer
  that reads too slowly loses old lines (the viewer says how many) rather than slowing the agent.
- Lines longer than 4 KiB are cut.
