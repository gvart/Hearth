# Prometheus

If you already run Prometheus with node-exporter, the hub can read from it and draw device charts
(CPU, memory, root disk usage over the last hour) in the device drawer. Hearth only reads; it never
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
