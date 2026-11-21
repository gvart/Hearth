---
title: Prometheus
description: Built-in device metrics, and device charts and metric triggers from an existing Prometheus.
---

## Built-in metrics

With no setup, every agent sends its host metrics to the hub every 15 s: `cpu`, `memory` and `disk`
(root filesystem) in percent, `temperature` (hottest thermal zone, Linux only) in °C, and `net_rx`
and `net_tx` in bytes per second. The hub keeps raw samples for 24 hours and one-minute, ten-minute
and hourly averages for 7 days, in `<data-dir>/metrics.db`, and prunes older data every 10 minutes.
Device charts use them when no Prometheus is configured:

```
GET /api/v1/devices/{id}/metrics?range=168h&names=cpu,temperature&source=builtin
```

`range` is 5m to 168h (default 1h), `names` limits the series, and `source` (`builtin` or
`prometheus`) overrides the default: Prometheus when it is configured, built-in otherwise.

The device list draws its sparklines from one request for all devices, always from the built-in
metrics, covering the last hour:

```
GET /api/v1/metrics/sparklines
```

`metrics.db` is local to each hub and not replicated: in a [cluster](cluster.md) each master records
the metrics of the agents streaming to it, so when an agent moves its charts continue on its new
master, and each hub's API shows what it recorded. A [metric trigger](automations.md#metric-threshold)
reads a device's newest value from the master its agent streams to. Deleting the file loses only history.

## Prometheus

If you already run Prometheus with node-exporter, the hub can read from it and draw device charts
(CPU, memory, root disk usage over 1 hour, 24 hours or 7 days) on the device's page. Hearth only reads; it never
writes to Prometheus or changes its scrape config.

## Configure

```sh
hearth hub --prometheus-url http://prometheus.lan:9090
# or
HEARTH_PROMETHEUS_URL=http://prometheus.lan:9090 hearth hub
```

The URL may carry a path prefix (`http://host/prometheus`) and basic-auth credentials
(`http://user:pass@host:9090`). On a cluster, set it on every hub: it is per-hub configuration, not
replicated state.

## How devices are matched

The hub queries `node_uname_info` and picks, for each device:

1. the target whose `nodename` label equals the device hostname (case-insensitive, short name or FQDN), else
2. the target whose `instance` host (port stripped) is the device hostname or one of its IP addresses.

Loopback and link-local addresses never match.

## When there is nothing to show

Charts never fail the UI. `GET /api/v1/devices/{id}/metrics` always answers 200 with a `status`:

| status           | meaning                                                  |
|------------------|----------------------------------------------------------|
| `ok`             | charts follow                                            |
| `not_configured` | no `--prometheus-url`                                    |
| `no_target`      | Prometheus has no node-exporter target for this device   |
| `unreachable`    | Prometheus did not answer, or answered with an error     |
