---
title: Neighbors and connections
description: See who each device talks to, from the device itself, without router access.
---

An agent can report what its device sees of the network: the entries of its neighbour (ARP) table,
and a summary of its established TCP connections. The hub turns each address into the enrolled
device, the hub itself or the [discovered host](discovery.md) it belongs to, and shows them in the
device's drawer under **Neighbors and connections**. No router, switch or conntrack access needed.

## Turn it on, per device

Connections say who talks to whom, so an agent reports nothing until you start it with
`--allow-net-edges`:

```sh
hearth agent run --allow-net-edges
```

The flag is part of the device's [capability ceiling](guardrails.md#device-capability-ceiling): the
hub cannot turn it on from its side, and drops a report from an agent whose ceiling does not allow
it. Drop the flag and restart the agent, and the hub forgets what it reported before.

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
reads once when the drawer opens; **Refresh** reads again.

Every read is the policy action `device.net_edges` (class `read`) and is audited, as opening a log
stream is. The API is `GET /api/v1/devices/{id}/net-edges`.
