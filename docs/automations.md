# Automations

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

Built in: the triggers below and the actions in [Actions on devices and webhooks](#actions-on-devices-and-webhooks).

## Triggers

| type       | fires when                                                    |
|------------|---------------------------------------------------------------|
| `manual`   | run by hand                                                   |
| `device`   | a device goes online or offline                               |
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
```

or any PromQL query, which fires when any of its series is past the threshold:

```yaml
triggers:
  - type: metric
    query: 'up{job="pihole"}'
    below: 1
    for: 1m
```

Metrics come from Prometheus, so the metric trigger needs `hearth hub --prometheus-url` (see
[prometheus.md](prometheus.md)); devices map to node-exporter targets as for charts. Without it the
automation loads, but its metric trigger stops with an error in the hub log. A value that cannot be
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

Checks run from the hub (the leader, in a cluster). Running them from an agent is tracked in
[#105](https://github.com/gvart/Hearth/issues/105).

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

## How the hub runs them

- The hub checks the directory every 2 s. A new or changed file is loaded; a changed automation
  is stopped (its run in progress cancelled) and started again; a removed one is stopped. If any
  file is invalid, the reload is refused as a whole and logged, and the automations already running
  carry on.
- In a cluster, automations run on the leader only, and move with leadership. Each hub reads its own
  directory, so keep it the same on every hub.
- Every action goes through policy with actor `automation/<id>`, and is in the audit log.
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
  - id: notify
    type: webhook
    url: https://ntfy.sh/my-lab
    method: POST                 # default POST
    headers: {Title: DNS restarted}
    body: pi4 restarted pihole-FTL
    timeout: 10s                 # optional, default 10s, at most 1m
```

Two gates stand before anything runs on a device, and both must agree:

- **Hub policy.** `exec` is dangerous: an automation may take it only when the hub grants it by id,
  `hearth hub --allow-dangerous-automation disk-report` (repeatable; in a cluster, give every hub
  the same flags). Without the grant the action is denied. Approving dangerous actions one at a time
  comes later.
- **The device's capability ceiling.** An agent runs only what its own flags allow, and nothing by
  default. The hub can never raise it:

  ```sh
  hearth agent run --allow-restart systemd:pihole-FTL.service --allow-restart docker:jellyfin \
    --allow-exec /usr/bin/df
  ```

  `--allow-exec` matches the command's first word exactly as the automation writes it, with any
  arguments. `--allow-restart` takes `systemd:UNIT`, `systemd-user:UNIT` or `docker:CONTAINER`. On
  a systemd install, add the flags to `ExecStart=` with `systemctl edit hearth-agent`.

A denial by either gate stops the run with status `denied`, shown in `hearth automation runs`, and
is in the audit log with actor `automation/<id>`. A failed action (non-zero exit, a non-2xx answer,
an offline device) stops it with status `failed`.

Webhook URLs and headers often carry secrets: errors, logs and the audit log name only the URL's
scheme and host. Command arguments are never logged either; a failed command's error ends with up
to 256 bytes of its stderr.
