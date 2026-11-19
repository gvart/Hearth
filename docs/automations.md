---
title: Automation reference
description: Triggers, conditions, actions and templates of automation YAML files.
---

An automation is a YAML file in the hub's automations directory: `<data-dir>/automations` by default,
or `hearth hub --automations-dir DIR`. Every `*.yaml` and `*.yml` file in it (not in subdirectories)
is one automation. Keep the directory in git.

```yaml
id: hello                  # lowercase letters, digits, - and _; unique across files
description: Say hello.    # optional
mode: single               # single (default), queued or restart
triggers:                  # any of these starts a run
  - id: by-hand            # step ids are optional: the default is <type>-<position>
    type: manual
conditions: []             # optional: all must hold, or the run is skipped
actions:                   # run in order; the first failure or policy denial ends the run
  - id: greet
    type: log
    description: write a line to the hub log
    message: hello from Hearth
```

`mode` says what happens when a trigger fires while a run is in progress: `single` ignores it,
`queued` runs it afterwards (at most 10 waiting), `restart` cancels the current run and starts again.

Built in: the triggers below and the actions in [Actions on devices and webhooks](#actions-on-devices-and-webhooks)
and [Kubernetes actions](#kubernetes-actions).
No condition types are built in yet: `conditions` must be left out or empty, and a condition of any
type is rejected when the file is loaded.

## Triggers

| type       | fires when                                                    |
|------------|---------------------------------------------------------------|
| `manual`   | run by hand (there is no command or button for it yet)        |
| `device`   | a device goes online or offline                               |
| `network`  | network discovery finds a new host, or one back after an hour |
| `metric`   | a metric has been above or below a threshold for a duration   |
| `http`     | an HTTP GET fails or returns the wrong status                 |
| `dns`      | a DNS server does not resolve a name                          |
| `tcp`      | a TCP port does not accept connections                        |
| `schedule` | a cron schedule comes due                                     |

### Device online/offline

```yaml
triggers:
  - type: device
    device: nas        # device id, name or hostname; leave out for any device
    to: offline        # online or offline
```

A device goes offline when the hub has not heard from its agent for 30 s.

### Network hosts

```yaml
triggers:
  - type: network
    event: new         # new or returned; leave out for both
    batch: true        # optional: one firing per scan instead of one per host
```

Fires once for each host a [network discovery](discovery.md) scan finds for the first time (`new`),
or finds again after an hour or more unseen (`returned`). Hosts marked known or ignored on the
Devices page, and hosts that are an enrolled device's interface, never fire it. Use `mode: queued`
so that several hosts found by one scan each get their run, up to 11 at a time: the rest are dropped.

With `batch: true` a scan fires once for its new hosts and once for its returned hosts, however many
it found, so none are dropped. `.Trigger.Count` is how many hosts it found and `.Trigger.Hosts` lists
them, one per line. The list fits in one notification: it always holds at least 50 hosts, and ends
with `and N more` when there are too many. The other fields are those of the first host. The hub's
built-in [new-device alerts](discovery.md#new-device-alerts) automation is made of this trigger.

### Metric threshold

`cpu > 90 for 5m`:

```yaml
triggers:
  - type: metric
    device: nas        # id, name or hostname
    metric: cpu        # cpu, memory or disk (root filesystem), in percent
    above: 90          # or below:
    for: 5m            # optional: how long it must stay past the threshold
    every: 30s         # optional: how often to read it (default 30s)
    timeout: 5s        # optional: per read (default 5s, or every if shorter)
```

or any PromQL query, which fires when any of its series is past the threshold:

```yaml
triggers:
  - type: metric
    query: 'up{job="pihole"}'
    below: 1
    for: 1m
```

With `hearth hub --prometheus-url` (see [Prometheus](prometheus.md)), metrics come from Prometheus,
and devices map to node-exporter targets as for charts. Without it, a `device` metric is the newest
of the [built-in metrics](prometheus.md#built-in-metrics) the device's agent sent, if it is under a
minute old; a `query` needs Prometheus, and its trigger stops with an error in the hub log. A value that cannot be
read does not count as past the threshold, and starts the `for` duration over. A metric trigger
fires once per spell past the threshold: again only after the value has come back.

### Synthetic checks: HTTP, DNS, TCP

```yaml
triggers:
  - type: http
    url: http://grafana.lan:3000/api/health
    status: 200          # optional: the status to expect; default any 2xx or 3xx
  - type: dns
    name: example.com    # asks for its A record
    server: 192.168.1.2  # the DNS server to ask (e.g. Pi-hole): host or host:port, default port 53
  - type: tcp
    address: nas.lan:22
```

Every check also takes `every` (how often; default 10s), `timeout` (per check; default 5s, or
`every` if shorter) and `for` (how long it must keep failing; default 0: the first failure fires).
A check fires once per outage: again only after it has passed. The DNS check asks the server
directly over UDP, so the hub's own resolver and `/etc/hosts` play no part. With the defaults, a
stopped Pi-hole is noticed within about 15 s.

An HTTP check's URL is shown (in plans, logs, run history and templates) with its password and
query values replaced by `REDACTED`, as health-check URLs often carry a token.

Checks run from the hub (the leader, in a cluster), unless they set `from`: a device (id, name or
hostname) whose agent runs the check instead, to test a service from inside a VLAN, or one bound
to the device's localhost, that the hub cannot reach:

```yaml
triggers:
  - type: http
    url: http://127.0.0.1:8080/health   # as the device sees it
    from: pi5
    for: 20s
```

A check from a device:

- needs the device's agent to allow it: `hearth agent run --allow-probe`. It is off by default:
  the check only connects and reads, but it lets the hub use the device as a vantage point into
  any network the device can reach. The agent reports the setting with its ceiling; the hub
  refuses to send a check to an agent without it, and the agent refuses it again. Agents older
  than this release cannot run checks.
- goes through policy as `automation.probe` (class `read`), once when the trigger starts (at hub
  start, on gaining leadership, when its file changes), with one audit entry; the checks then run
  under that decision. A denial (by policy, or because the device's reported ceiling does not
  allow probes) stops the trigger, logged as `automation trigger stopped`.
- takes a `timeout` of at most 1m.
- does not fire while it cannot run (the agent is offline, too old, or refuses the check): that is
  neither a failure nor a recovery, so an outage in progress neither fires again nor ends. The hub
  logs a warning once when the check stops running and again when it runs once more. Pair it with
  a `device` trigger (`to: offline`) to hear about the agent itself.

The agent never logs the URL it checks.

### Schedule

```yaml
triggers:
  - type: schedule
    cron: "0 3 * * *"    # minute hour day-of-month month day-of-week
```

Standard five-field cron, or `@hourly`, `@daily`, `@weekly`, `@monthly`, `@every 15m`. It runs in
the hub's local time unless the spec starts with a zone: `CRON_TZ=Europe/Berlin 0 3 * * *`. Times
missed while no hub was leading are not made up.

## Checking a file

```sh
hearth automation plan automations/hello.yaml
```

validates the file and prints what the automation would do, without running anything. Problems are
reported with their line, as `file:line: message`.

## The visual editor

The web UI's **Automations** page lists the files of the automations directory, and edits them as
trigger, condition and action blocks or as YAML. Both views change the same file: switch between them
at any time. The file stays the source of truth, so keep it in git as before.

- **Your file stays yours.** An edit replaces only the text of what you changed: every other byte of
  the file, comments, key order, quoting and spacing included, stays as written. An edit that cannot
  be made that way is refused, and the editor sends you to the YAML view.
- **What the form cannot show is kept.** A step with a type the editor has no form for, YAML anchors,
  aliases or tags, a key it does not know, or a value of an unexpected shape appears as a read-only
  YAML block. So does a value the form could change by showing it: a number such as `010` or `0750`,
  which is not the number it looks like, and a list item or header with spaces around it. It is written
  back untouched; change it in the YAML view. A file that does not parse opens in the YAML view only,
  and so does a file holding the invisible characters U+0085, U+2028 or U+2029, or a carriage return
  with no line feed after it, which the hub reads as line breaks, or defining one anchor name twice.
  The form refuses those characters too.
- **Dry run** sends the file to the hub, which validates it as it would when loading it, and asks
  policy about saving it and about each action, as the automation would ask when it runs. Each
  decision is shown (allowed, needs approval, denied) and audited with the result `dry-run`. Nothing
  is saved, no trigger starts and no action runs. A check that runs `from` a device is decided when
  its trigger starts, and is not part of the dry run.
- **Save** needs a signed-in session. The hub validates the file again, with the notification channels
  and other settings it really has, and refuses it, with the line of each problem, if it would not load.
  It also refuses a save when another file of the directory is invalid, since one invalid file stops
  the reload of all of them, when the file changed on disk since you opened it, and when the file has
  more than 64 steps. The form is locked until the save is answered.

Saving goes through policy as `automation.apply` (class `dangerous`) with actor `web/<address>`. The
audit log, and any approval, show the file's name, its SHA-256 and its steps by id and type. Commands,
messages, queries and descriptions may hold secrets, so they stay out of the audit log and out of
approval notifications. The plan, with each command and its device, is shown only on the
**Approvals** page to someone signed in; an approval link says to sign in to read it. Of a webhook
even the plan shows only the site. To require approval for saves, or to forbid them:

```yaml
actors:
  web:
    dangerous: confirm   # or deny
```

With `confirm`, the save finishes once someone approves it on the **Approvals** page. That setting
covers every dangerous action from the web UI.

A save of a file with a dangerous action that policy would let the automation run without asking
anyone, through [`dangerous_automations`](guardrails.md) or an `allow` mode for automations, always
waits for approval, whatever the modes say about saves, and is refused if the hub cannot hold
approvals: saving is the last moment a person sees what the file does. A mode of `deny` for the web UI
still denies it. The person who made the save may approve it.

An automation's id cannot be changed in the editor: create a new one and remove the old file. Files
that are symbolic links are not opened or saved here, and nothing of what they point to is shown. The
built-in [new-device alerts](discovery.md#new-device-alerts) automation has no file, so it is not
listed. In a cluster, a save writes to the directory of the hub you are connected to only, and the
editor names that hub. Only the leader runs automations, so copy the file to the other hubs, as
[configuration drift](cluster.md#configuration-drift) will remind you.

## How the hub runs them

- The hub checks the directory every 2 s. A new or changed file is loaded; a changed automation
  is stopped (its run in progress cancelled) and started again; a removed one is stopped. If any
  file is invalid, the reload is refused as a whole and logged, and the automations already running
  carry on.
- In a cluster, automations run on the leader only, and move with leadership. Each hub reads its own
  directory, so keep it the same on every hub.
- Every action goes through policy with actor `automation/<id>`, and is in the audit log.
  `hearth hub --automations-dry-run` sends every action to policy as a dry run: the decisions are
  audited (result `dry-run`) and nothing runs. Kubernetes actions are also planned (see
  [Kubernetes actions](#kubernetes-actions)).
- Runs are kept in the run history (the newest 100 per automation):

  ```sh
  hearth automation runs [automation-id]
  ```

  After a rolling upgrade, runs are recorded once `hearth cluster migrate` brings the cluster to
  schema 7.

## Actions on devices and webhooks

| type      | does                                              | policy class | runs on |
|-----------|---------------------------------------------------|--------------|---------|
| `log`     | writes a line to the hub log                      | read         | hub     |
| `webhook` | sends one HTTP request                            | safe         | hub     |
| `notify`  | sends a notification (ntfy, Telegram)             | safe         | hub     |
| `restart` | restarts a systemd unit or Docker container       | safe         | device  |
| `exec`    | runs a command                                    | dangerous    | device  |

```yaml
actions:
  - id: restart-dns
    type: restart
    device: pi4                  # device id, name or hostname
    service: systemd:pihole-FTL.service   # or systemd-user:UNIT (systemctl --user), docker:CONTAINER
    timeout: 1m                  # optional, default 1m, at most 10m
  - id: disk-report
    type: exec
    device: pi4
    command: [/usr/bin/df, -h]   # a list: program, then arguments; never a shell
    timeout: 1m                  # optional, default 1m, at most 10m
  - id: notify
    type: webhook
    url: https://ntfy.sh/my-lab
    method: POST                 # default POST
    headers: {Title: DNS restarted}
    body: pi4 restarted pihole-FTL
    timeout: 10s                 # optional, default 10s, at most 1m
```

Two gates stand before anything runs on a device, and both must agree:

- **Hub policy.** `exec` is dangerous: by default an automation may take it only when the hub
  grants it by id, `hearth hub --allow-dangerous-automation disk-report` (repeatable; or
  `dangerous_automations` in the policy file; in a cluster, give every hub the same). Without the
  grant the action is denied, or held for approval if the policy file says `confirm` (see
  [guardrails.md](guardrails.md)).
- **The device's capability ceiling.** An agent runs only what its own flags allow, and nothing by
  default. It reports its ceiling to the hub, which refuses anything beyond it before sending it
  (and denies it in policy), and the agent refuses it again. The hub can never raise it:

  ```sh
  hearth agent run --allow-restart systemd:pihole-FTL.service --allow-restart docker:jellyfin \
    --allow-exec /usr/bin/df
  ```

  `--allow-exec` matches the command's first word exactly as the automation writes it, with any
  arguments. `--allow-restart` takes `systemd:UNIT`, `systemd-user:UNIT` or `docker:CONTAINER`.
  `--allow-probe` lets checks run from the device (see above). On
  a systemd install, add the flags to `ExecStart=` with `systemctl edit hearth-agent`.

A denial by either gate stops the run with status `denied`, shown in `hearth automation runs`, and
is in the audit log with actor `automation/<id>`. A failed action (non-zero exit, a non-2xx answer,
an offline device) stops it with status `failed`.

A `notify` action sends to a channel configured on the hub, by name: see
[Notifications](notifications.md).

## Kubernetes actions

The [Kubernetes actions](kubernetes.md#actions) of the web UI, on a cluster the hub has adopted,
named by its name in Hearth:

| type              | does                                                         | policy action           | class     |
|-------------------|--------------------------------------------------------------|-------------------------|-----------|
| `kube_restart`    | rolling restart of a Deployment, StatefulSet or DaemonSet    | `kube.workload.restart` | safe      |
| `kube_scale`      | sets the replicas of a Deployment or StatefulSet             | `kube.workload.scale`   | safe      |
| `kube_delete_pod` | deletes a pod; its controller, if any, recreates it          | `kube.pod.delete`       | safe      |
| `kube_cordon`     | marks a node unschedulable                                   | `kube.node.cordon`      | safe      |
| `kube_uncordon`   | marks a node schedulable again                               | `kube.node.uncordon`    | safe      |
| `kube_drain`      | cordons a node and evicts its pods, honouring PodDisruptionBudgets | `kube.node.drain` | dangerous |

```yaml
id: nightly-web
triggers:
  - type: schedule
    cron: "0 4 * * *"
actions:
  - id: restart-web
    type: kube_restart
    cluster: homelab             # the cluster's name on the Kubernetes page
    kind: Deployment             # Deployment, StatefulSet or DaemonSet (scale: not DaemonSet)
    namespace: default
    name: web
  - type: kube_scale
    cluster: homelab
    kind: Deployment
    namespace: media
    name: jellyfin
    replicas: 0
  - type: kube_delete_pod
    cluster: homelab
    namespace: default
    name: web-7d9f8-abcde
  - type: kube_cordon            # and kube_uncordon
    cluster: homelab
    node: pi-2
  - type: kube_drain
    cluster: homelab
    node: pi-2
    timeout: 5m                  # optional, default 2m, at most 10m
```

- Policy decides on each one before anything is sent to the cluster, with actor `automation/<id>`
  and the target `<cluster>/<object>` the web UI's actions are audited with. A denied action sends no
  request at all, not even the reads of its plan.
- `kube_drain` is dangerous: like `exec`, an automation may take it only when the hub grants it by
  id (`hearth hub --allow-dangerous-automation <id>` or `dangerous_automations` in the policy file),
  or when the policy file says `confirm` and an operator approves it (see [guardrails.md](guardrails.md)).
  Without either, it is denied.
- A drain that runs out of time stops, leaves the node cordoned and fails the run, naming the pods
  still there.
- With `hearth hub --automations-dry-run`, a Kubernetes action policy would allow is planned
  instead: the hub reads the objects involved, as the web UI's dry run does, and records the plan
  (summary, steps, warnings) in the run's step and the hub log. Nothing is changed.

`cluster`, `namespace`, `name` and `node` may be templates; `kind`, `replicas` and `timeout` may not.

Webhook URLs and headers often carry secrets: errors, logs and the audit log name only the URL's
scheme and host. Command arguments are never logged either; a failed command's error ends with up
to 256 bytes of its stderr.

## Using the trigger's event in actions

Some action fields are [Go templates](https://pkg.go.dev/text/template) over the event that started
the run, so one automation can act on whichever device went offline:

```yaml
id: revive
triggers:
  - id: down
    type: device
    to: offline                  # no device: any device
actions:
  - type: restart
    device: "{{ .Trigger.Device }}"
    service: systemd:hearth-agent.service
  - type: webhook
    url: https://ntfy.sh/my-lab
    headers: {Title: "{{ .Trigger.Name }} is {{ .Trigger.State }}"}
    body: "{{ .Trigger.Hostname }} went {{ .Trigger.State }} at {{ .Trigger.At }}"
```

Templated fields: `device` (exec, restart), `body` and header values (webhook), `message` (log),
`title` and `message` (notify), `cluster`, `namespace`, `name` and `node` (kube_*).
The webhook `url`, `command` and `service` are not templates.

| field                  | trigger types              | value                                              |
|------------------------|----------------------------|----------------------------------------------------|
| `.Trigger.ID`          | all                        | the trigger's id                                   |
| `.Trigger.Type`        | all                        | its type: `device`, `metric`, ...                  |
| `.Trigger.At`          | all                        | when it fired, RFC 3339 in UTC                     |
| `.Trigger.Device`      | device                     | the device's id                                    |
| `.Trigger.Name`        | device                     | the device's name                                  |
| `.Trigger.Hostname`    | device                     | the device's hostname                              |
| `.Trigger.State`       | device                     | `online` or `offline`                              |
| `.Trigger.Event`       | network                    | `new` or `returned`                                |
| `.Trigger.MAC`         | network                    | the host's MAC address, lower-case                 |
| `.Trigger.IP`          | network                    | the address it answered on                         |
| `.Trigger.Vendor`      | network                    | from the MAC, or empty                             |
| `.Trigger.Name`        | network                    | its mDNS or reverse DNS name, or empty             |
| `.Trigger.Private`     | network                    | `true` for a randomized ("private") MAC            |
| `.Trigger.Count`       | network with `batch: true` | how many hosts the scan found                      |
| `.Trigger.Hosts`       | network with `batch: true` | those hosts, one per line, then `and N more` if cut |
| `.Trigger.Device`      | metric with `device`       | the device as the trigger names it                 |
| `.Trigger.Value`       | metric                     | the value past the threshold (a number)            |
| `.Trigger.Target`      | http, dns, tcp             | the URL (password and query values hidden), name or address checked |
| `.Trigger.Error`       | http, dns, tcp             | why the check failed                               |

Only text/template's built-in functions are there (`printf`, `eq`, `if`, ...): format a value with
`{{ printf "%.1f" .Trigger.Value }}`. A field the event does not have is an error, never an empty
string, and it is caught when the file is loaded: every template is tried against each trigger of
its automation, so `{{ .Trigger.Device }}` next to a `schedule` trigger is rejected with its line.
A `device` that renders empty fails the run.

Templates are bounded, so that a file cannot exhaust the hub. Each time a field renders, it may
produce at most 1 MiB, build at most 8 MiB of text along the way, and take at most 100,000 steps and
2 seconds. A `printf` width or precision may have at most 3 digits. A render over a limit fails that
run with an error naming the limits.

What happens to a file that goes further depends on how it reaches the hub:

| | File on disk, or applied over MCP | Saved in the web UI |
|---|---|---|
| Template over a limit for its sample event | Loads, with a warning in the hub log naming the file. Runs that reach it fail. | Refused |
| `define`, `template` or `block` | Loads and runs | Refused |

A file on disk never stops the rest of the directory loading because of these limits. To change a
file that uses `define`, `template` or `block`, edit it on the hub.

`hearth automation plan` shows templates as written, and lists the fields each trigger provides.
Policy decides on, and the audit log records, the rendered device. Run history keeps the trigger's
fields as the first step of each run.
