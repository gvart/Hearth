---
title: Exec plugins
description: Write a Hearth integration in any language, as a program that speaks JSON lines over stdin and stdout.
---

An exec plugin is a program, in any language, that the hub runs as a child process and talks to in
JSON lines over its stdin and stdout. It reports devices and their entities (sensors, switches),
pushes their state, and offers commands. Every command goes through Hearth's policy, with the class
its manifest declares, and lands in the audit log.

Plugins are off unless you turn them on: the hub runs a plugin only when you name its manifest with
`--plugin`.

Two examples live in the repository:

- [`examples/plugins/go-lamp`](https://github.com/gvart/hearth/tree/main/examples/plugins/go-lamp):
  a virtual lamp in Go, with `turn_on` and `turn_off` commands.
- [`examples/plugins/python-load`](https://github.com/gvart/hearth/tree/main/examples/plugins/python-load):
  the hub host's load average in Python, pushed every few seconds, with a `refresh` command.

## Run a plugin

```sh
cd examples/plugins/go-lamp && go build -o lamp .
hearth hub --plugin ./plugin.yaml --plugin ../python-load/plugin.yaml
```

| Flag | Env | |
| --- | --- | --- |
| `--plugin` | `HEARTH_PLUGINS` (comma-separated) | Manifest of a plugin to run. Repeatable. Default: none. |

The hub reads every manifest when it starts and refuses to start if one is invalid. To change a
plugin's manifest, restart the hub.

On a hub cluster, every hub runs the plugins of its own `--plugin` flags. A command runs on the hub
that receives it.

## The manifest

The manifest is a YAML file next to the plugin. You write it, or review the one the plugin's author
ships: it says what the hub runs and what the plugin may do. Nothing the plugin prints can change it.

```yaml
protocol: 1            # the protocol version the plugin speaks
name: go-lamp          # letters, digits, '.', '_' and '-'; up to 64
version: 0.1.0         # shown and audited
command: ./lamp        # relative to this file, absolute, or a bare name looked up in the hub's PATH
args: []               # passed as is: no shell ever runs
env:                   # the plugin's environment, on top of PATH and HEARTH_PLUGIN
  LAMP_ADDR: 192.168.1.40
capabilities: [discover, state, command]
commands:
  - name: turn_on
    class: safe        # read, safe or dangerous
    description: Turn the lamp on
```

| Field | |
| --- | --- |
| `capabilities` | What the plugin may do. `discover`: report devices. `state`: push entity states. `command`: run the commands below. A message the manifest's capabilities do not allow is a protocol violation. |
| `commands` | The only commands the hub sends the plugin, each with its [policy class](guardrails.md). Commands need the `command` capability. |

### Who may change a plugin

Whoever can change a plugin's manifest, its program, or a script its `args` name (such as
`plugin.py`) runs code as the hub's user. So on Linux and macOS the hub refuses each of them, and
every directory above them, unless it is owned by the hub's user or root and no one else can write
it. A root-owned sticky directory, such as `/tmp`, is allowed. The hub checks the manifest when it
starts, and the program and scripts again before every start and restart. The error names the fix,
such as `run chmod go-w /opt/plugins/lamp/lamp`.

- `go build` under umask 002 (the default for users with a group of their own, as on Ubuntu)
  writes a group-writable binary: `chmod g-w lamp` after building.
- Homebrew's Python lives in a group-writable Cellar and is refused. Name a trusted interpreter
  by its absolute path, such as `command: /usr/bin/python3`.
- The program's real path (after symlinks) and its SHA-256 go into every `plugin.start` audit
  entry, so the log shows exactly what ran.

`env` is for settings such as an API token. A manifest that sets `env` must be readable by its
owner only: `chmod 600 plugin.yaml`. The hub refuses one that group or others can read. 0600 is the
right mode for every manifest.

## Isolation

- The plugin runs as a child process of the hub, as the hub's user, in the manifest's directory.
  The hub starts it directly, without a shell.
- Its environment is clean: `PATH=/usr/local/bin:/usr/bin:/bin`, `HEARTH_PLUGIN` (the plugin's
  name) and the manifest's `env`. Nothing of the hub's own environment reaches it.
- Every start, and every restart, is the audited hub action `plugin.start` (class `dangerous`,
  actor `hub/plugins`). Naming the manifest with `--plugin` is the grant. If the audit log cannot
  take the entry, the plugin does not start.
- A plugin that crashes, hangs (does not answer a ping or a discover in time), prints a line that is
  not JSON, prints a line longer than 1 MiB, prints more than 200 lines a second, or breaks the
  protocol in any other way is killed and started again, with a backoff that doubles from 1 second
  up to 5 minutes. It starts over from 1 second once the plugin has run for a minute. The hub and
  its other plugins carry on.
- The hub keeps the last 20 lines the plugin printed on stderr, each cut to 512 bytes, and returns
  them to signed-in admins with its status (`GET /api/v1/plugins`). It never writes the plugin's
  output to its own log. Do not print secrets to stderr.
- The hub stops a plugin by killing it. On Linux and macOS the plugin runs in a process group of its
  own and the hub kills the whole group, so a wrapper (`sh`, `npx`, `uv run`) leaves nothing behind.
  On Linux the kernel also kills the plugin should the hub die without stopping it.
- At most 32 commands are in flight per plugin. More get 503 at once; the plugin is not touched.

## Commands and policy

A command runs through policy as `plugin.command.read`, `plugin.command.safe` or
`plugin.command.dangerous`, after the class its manifest declares. The audit entry's target is
`<plugin>/<command>`. Its detail holds the plugin, its version, the command and the device, never
the command's arguments, which may hold secrets.

| Action | Class | Actors |
| --- | --- | --- |
| `plugin.start` | dangerous | `hub` (fixed: the `--plugin` flag is the grant) |
| `plugin.command.read` | read | `web` |
| `plugin.command.safe` | safe | `web` |
| `plugin.command.dangerous` | dangerous | `web` |

A command the manifest does not declare is denied, and audited as a denied
`plugin.command.dangerous`. The plugin never sees it. With no `policy.yaml`, a signed-in admin may
run commands of every class, as they may stop a Proxmox guest. To hold the dangerous ones for
approval, or deny them, set the class's mode for `web` in [`policy.yaml`](guardrails.md):

```yaml
actors:
  web:
    dangerous: confirm
```

## API

| | |
| --- | --- |
| `GET /api/v1/plugins` | Every plugin's status: state (`starting`, `running`, `restarting`, `stopped`), the last error, restarts, its commands, devices and entities with their last state, and the tail of its stderr. |
| `POST /api/v1/plugins/{name}/commands` | Runs a command: `{"command": "turn_on", "device": "lamp", "args": {}}`. Answers `{"output": "..."}`, 403 when policy denies it, 503 when the plugin is not running or already runs 32 commands, 502 when the plugin reports it failed. |

Both need the admin session. Without `--plugin` neither exists.

## Protocol, version 1

Every line on the plugin's stdin and stdout is one JSON object with a `type`. Write each message on
one line and flush stdout after it. Ignore message types and fields you do not know: newer hubs may
send more.

### Hello

The hub speaks first. The plugin answers with its protocol version, the name in its manifest
(which the hub passes in `HEARTH_PLUGIN`) and its version, within 10 seconds. Until it does, the
hub sends nothing else.

```json
{"type":"hello","protocol":1}
{"type":"hello","protocol":1,"name":"go-lamp","version":"0.1.0"}
```

### Ping

Every 30 seconds. Answer within 10 seconds, with the same `id`, or the hub restarts the plugin.
While a command is in flight the hub sends no ping and no discover, and a ping or discover that the
plugin does not answer in time is forgiven: a plugin may handle one message at a time, and the
command has its own timeout.

```json
{"type":"ping","id":"7"}
{"type":"pong","id":"7"}
```

### Discover

With the `discover` capability: once the plugin said hello, and every minute after. Answer with
every device, with the same `id`, within 30 seconds. The list replaces the one before. A plugin may
also send `devices` on its own, without an `id`, whenever its devices change.

```json
{"type":"discover","id":"8"}
{"type":"devices","id":"8","devices":[{"id":"lamp","name":"Desk lamp","kind":"light","entities":[{"id":"on","name":"On","kind":"switch","state":false}]}]}
```

| Field | |
| --- | --- |
| `id` | Device and entity ids: letters, digits, `.`, `_` and `-`; up to 64. Unique within the plugin, and within the device. |
| `name`, `kind`, `unit` | Free text, up to 128 bytes. `unit` is an entity's, such as `W` or `°C`. |
| `state` | An entity's state: any JSON value, up to 4 KiB. |

Up to 256 devices of up to 64 entities each.

### State

With the `state` capability, whenever an entity's state changes. A state of a device or entity the
plugin has not reported is dropped.

```json
{"type":"state","device":"lamp","entity":"on","state":true}
```

### Command

With the `command` capability, only for the commands the manifest declares, and only once policy
allowed them. `device` and `args` (a JSON object) are there when the caller gave them. Answer with
the same `id` within 30 seconds: `ok` and an `output` of up to 64 KiB, or an `error`.

```json
{"type":"command","id":"9","command":"turn_on","device":"lamp","args":{}}
{"type":"result","id":"9","ok":true,"output":"lamp is on"}
{"type":"result","id":"9","ok":false,"error":"the lamp does not answer"}
```

A plugin may handle commands one at a time or several at once: replies are matched by `id`.

## Not yet

- Plugins on agents, within the device's capability ceiling ([#223](https://github.com/gvart/hearth/issues/223)).
- Plugin devices in the device list and plugin commands in automations, runbooks and MCP ([#224](https://github.com/gvart/hearth/issues/224)).
