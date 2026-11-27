---
title: Neighbors and connections
description: See who each device talks to, from the device itself, without router access.
---

An agent can report what its device sees of the network: the entries of its neighbour (ARP) table,
and a summary of its established TCP connections. The hub turns each address into the enrolled
device, the hub itself or the [discovered host](discovery.md) it belongs to, and shows them in the
device's page under **Neighbors and connections**. No router, switch or conntrack access needed.

## Turn it on, per device

Connections say who talks to whom, so an agent reports nothing until you turn **Neighbors** on in
the device's **Capabilities** card, or from a hub host:

```sh
hearth device capabilities <device-id> --set net-edges=on
```

It is part of the device's [capability ceiling](guardrails.md#device-capability-ceiling): the hub
drops a report from an agent whose ceiling does not allow it. Turn it off again and the hub forgets
what it reported before. The agent's own `--allow-net-edges` flag turns it on from the device.

Only Linux agents report edges for now; on other systems the agent refuses the flag.

## What is reported

Shortly after the agent connects, then every minute:

- **Neighbors**: the complete entries of `/proc/net/arp`, as IP and MAC. A neighbour's MAC is how
  the hub tells which device or host it is, even when its address changed.
- **Connections**: the established TCP connections of `/proc/net/tcp` and `/proc/net/tcp6`, loopback
  excluded, grouped by peer, port and direction with a count. A connection to a port the device
  listens on (on that address, or on every address) is *inbound* and keyed by that port (sshd's
  22); any other is *outbound* and keyed by the peer's port (the hub's 7443). Ephemeral ports never
  make new entries.

Each report is capped at 512 neighbours and 512 connection groups; a host with more groups says how
many connections were left out. The agent reads the files any user may read, needs no privilege,
groups connections as it reads them, so a host with many sockets costs it no more, and keeps nothing
between reports. IPv6 neighbours (NDP) are not
reported yet.

The hub keeps each device's latest set in its own memory, as it keeps host metrics on its own: edges
never go into the replicated store. After a hub restart or a failover to another hub, the agents
refill them within a minute. The hub takes at most one report every 30 seconds from an agent.

## Reading them

Open a device and scroll to **Neighbors and connections**. Each peer shows as a device, `hub` (an
address of the hub's own interfaces) or a host network discovery found, or as unknown. The panel
reads once when the device's page opens; **Refresh** reads again.

Every read is the policy action `device.net_edges` (class `read`) and is audited, as opening a log
stream is. The API is `GET /api/v1/devices/{id}/net-edges`.

## The topology view

**Network**, on the Lab sheet, draws the edges of every device at once, as a graph:

- **Nodes**: the devices whose agents report edges, the hub's host, the hosts network discovery
  found and, unless you untick **Unknown addresses**, addresses the hub knows nothing of (internet
  peers, mostly).
- **Connections**: a solid line from client to server, the arrow at the server, labelled with the
  server's ports. When both ends report the same connection (both run with `--allow-net-edges`),
  it is drawn once.
- **Neighbours**: a dashed, lighter line between a device and an entry of its neighbour table. Untick
  **Neighbours** to see only who talks to whom.

Hover a node to bring out its own lines; click a device to open its page. A device whose agent
does not report edges contributes none, even when it reported some before; it can still show up as
the peer of a device that does.

The page reads once when it opens and again on **Refresh**, never on its own: the whole graph is one
read, the policy action `network.topology` (class `read`), audited once however many devices report.
The API is `GET /api/v1/net-edges`:

```json
{
  "reporting": 2,
  "updated_at": "2026-01-01T12:00:00Z",
  "nodes": [
    {"id": "device:4f1c", "kind": "device", "name": "pi", "device_id": "4f1c", "reports": true},
    {"id": "hub", "kind": "hub", "name": "hub host"},
    {"id": "host:aa:bb:cc:00:00:01", "kind": "host", "name": "router", "ip": "192.0.2.1"},
    {"id": "ip:198.51.100.9", "kind": "unknown", "name": "198.51.100.9", "ip": "198.51.100.9"}
  ],
  "edges": [
    {"kind": "connection", "from": "device:4f1c", "to": "hub", "port": 7443, "count": 1},
    {"kind": "neighbor", "from": "device:4f1c", "to": "host:aa:bb:cc:00:00:01"}
  ]
}
```

`reporting` is how many agents report edges; with none, the page says how to turn them on. A
connection's `from` is the client and `to` the server, whose `port` it is; `count` is the most either
end reported.
