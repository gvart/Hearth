---
title: Telemetry
description: The anonymous usage stats a hub sends only if you opt in, exactly what they hold, and how to turn them off.
---

Hearth can send a few anonymous usage stats, so the project can count how many homelabs run it and
what they use. **It is off by default.** Nothing is sent until an admin says yes.

## Opting in

After you sign in to the web UI for the first time, a card asks **Share anonymous usage stats?** and
lists what would be sent. Your answer is stored in the hub's database and shared by every hub of a
cluster. Until you answer, and after you answer no, nothing is sent.

To change your answer later, use the line at the bottom of any page: **Share** or **Stop sharing**.
Every change is the policy action `telemetry.set` (class `safe`, actor `web`, signed-in admin only),
recorded in the audit log.

## What is sent

One JSON object, with these keys and nothing else:

| Key            | What it holds                                                                                   |
| -------------- | ----------------------------------------------------------------------------------------------- |
| `install_id`   | A random ID, made when you say yes. It is derived from nothing on the host: not the hardware, not the CA. Saying no forgets it; saying yes again makes a new one |
| `version`      | The hub's Hearth version                                                                        |
| `os`           | The hub's operating system (`linux`, `darwin`, `windows`)                                        |
| `arch`         | The hub's CPU architecture (`amd64`, `arm64`, ...)                                               |
| `devices`      | How many devices the hub has enrolled, as a range: `0`, `1-5`, `6-20`, `21-50` or `51+`           |
| `integrations` | Which kinds of integration are on, from this list only: `beszel`, `dhcp`, `discovery`, `kubernetes`, `netalertx`, `pihole`, `prometheus`, `proxmox` |

For example:

```json
{
  "install_id": "K3V7Q2M5XWJ4RBN6TF2YHC7D5A",
  "version": "v0.4.0",
  "os": "linux",
  "arch": "arm64",
  "devices": "6-20",
  "integrations": ["kubernetes", "pihole", "prometheus"]
}
```

Nothing else is sent: no IP addresses, hostnames, device names, cluster or server names, URLs,
credentials, facts, metrics or audit entries. The hub reads only the counts it needs to fill these keys.
The agents send nothing at all.

## When it is sent

- Shortly after you say yes (within a minute), then once a week.
- As one HTTPS `POST`, with a 10 second timeout. A send that fails is not retried until the next week,
  and is logged only at debug level.
- In a cluster, only the leader sends.

## Where it goes

To the collector at the hub's built-in endpoint, a small Cloudflare Worker whose source is in
[`deploy/telemetry-worker/`](https://github.com/gvart/hearth/tree/main/deploy/telemetry-worker). It
checks that each payload has exactly the keys above, keeps one row per install ID per week, and stores
no IP address.

`--telemetry-endpoint` (env `HEARTH_TELEMETRY_ENDPOINT`) sends to another `https://` URL instead, such
as your own copy of the worker. An empty endpoint sends nothing: the answer is stored, and the hub logs
once that nothing is sent. Builds without a built-in endpoint behave this way until you set one.

## Turning it off for good

Start the hub with `--telemetry=off` or `HEARTH_TELEMETRY=off`. This overrides everything, a stored
yes included: nothing is sent, the web UI does not ask, and the bottom of the page says telemetry is
turned off on the hub. `off` is the only value accepted; any other value stops the hub from starting.
