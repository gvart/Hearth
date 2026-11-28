---
title: Logs
description: Tail journald units, Docker containers and Kubernetes pods from the UI.
---

Debugging starts with logs. Hearth streams them on demand from the device and stores nothing: open a
device in the UI, pick a log under **Logs**, and its last lines appear, followed by new ones as they
are written. Close the view and the device stops reading.

## Allow a log on the device

Logs can hold secrets (tokens in URLs, passwords in a failed command line), so an agent streams
nothing until its [capability ceiling](guardrails.md#device-capability-ceiling) allows the source.
Turn **Logs** on in the device's **Capabilities** card (every source), or **Restrict to…** some. From
a hub host:

```sh
hearth device capabilities <device-id> --set logs=on
hearth device capabilities <device-id> --set 'logs=systemd:pihole-FTL.service,docker:*,systemd-user:backup-*'
```

The agent applies it at once, and ends a stream it no longer allows. Its own `--allow-logs` flag,
repeatable, allows a source from the device instead.

Each entry is `manager:name`, where the name may be a glob (`*`, `?`, `[...]`):

| Entry | Streams |
| --- | --- |
| `systemd:UNIT` | `journalctl --unit=UNIT --follow` |
| `systemd-user:UNIT` | `journalctl --user-unit=UNIT --follow`: the agent user's own `systemctl --user` units |
| `docker:CONTAINER` | `docker logs --follow --timestamps CONTAINER`, stdout and stderr |
| `eventlog:CHANNEL` | the Windows event log channel `CHANNEL` (`Application`, `System`, `Microsoft-Windows-PowerShell/Operational`), Windows only |

`systemd:*` does not cover user units, and the agent runs no shell: the name is passed to
`journalctl` or `docker` as one argument, or to the Windows Event Log API as the channel.

**Windows.** "Logs on" allows the systemd and Docker sources, not the event log: allow its channels
by name, for example `--set 'logs=eventlog:Application,eventlog:System'`. A glob does not cross a
`/`, so `eventlog:*` covers `Application`, `System`, `Setup` and other top-level channels but not
`Microsoft-Windows-…/Operational` ones: name those, or allow `eventlog:*/*`. `eventlog:Security`
holds sign-in events: allow it only if you mean to. Each event is one line: its level, provider
and event ID, then its message (rendered from the provider's message file, or its data values when
it has none), at most 4 KiB. The agent's user needs read access to the journal (root,
or the `systemd-journal` or `adm` group, for system units, and for user units where the journal is
not split per user) and to the Docker socket.

## In the UI

The device's page lists the allowed sources. An exact entry opens at once; a glob asks for the unit
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
  lines. Agents older than protocol 1.5 cannot stream logs: the UI says the agent is too old.
- Streams of the same source on a device share one `journalctl` or `docker logs` process and a ring
  of its last 500 lines, so a second viewer starts at once. When the last viewer closes, the process
  is stopped and the ring dropped: nothing is kept for a source nobody reads.
- When the browser goes away (tab closed, network lost) the hub tells the agent to stop. A viewer
  that reads too slowly loses old lines (the viewer says how many) rather than slowing the agent.
- Lines longer than 4 KiB are cut.
- On Windows the agent reads the event log through `wevtapi.dll` (`EvtSubscribe` for new events,
  a reverse `EvtQuery` for the last ones): no process is started. An event whose XML is over
  256 KiB shows as unreadable, and a message over 32 K characters gives way to the event's data.
