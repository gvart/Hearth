---
title: Network discovery
description: See every host on the LAN, not only the devices with an agent.
---

Network discovery finds the hosts on your LAN that have no agent (the router, a printer, a TV, a
phone) and lists them under **On your network** on the Devices page, with their IP, MAC address,
vendor and name. Each one has an **Add device** button that opens the usual
[install-and-join flow](getting-started.md).

Discovery is off until you turn it on. Nothing it learns leaves your LAN.

## Turn it on

```sh
hearth hub --discover-subnet 192.168.1.0/24
# or the hub's own LANs (each private IPv4 subnet, narrowed to its /24)
hearth hub --discover-subnet auto
# or
HEARTH_DISCOVER_SUBNETS=192.168.1.0/24,192.168.20.0/24 hearth hub
```

| Flag | Env | Default | |
| --- | --- | --- | --- |
| `--discover-subnet` | `HEARTH_DISCOVER_SUBNETS` (comma-separated) | off | IPv4 CIDR, or `auto`; repeatable |
| `--discover-interval` | `HEARTH_DISCOVER_INTERVAL` | `5m` | Time between scans |

The hub scans once at start and then every interval. A scan of a /24 takes about 5 seconds. Subnets
must be IPv4, at most 1024 addresses in all (a /22), and directly attached to the hub: the sweep sees
only hosts on the hub's own layer-2 network, not hosts behind a router.

## How a scan works

1. **ARP sweep, without privileges.** The hub sends one empty UDP datagram to the discard port (9)
   of every address in the subnet, twice, about 250 ms per /24. To send it, the kernel must resolve
   each address's MAC, so it ARPs for all of them. No port is probed and no raw socket is opened.
2. **Neighbour table.** The hub reads the OS neighbour (ARP) table: `/proc/net/arp` on Linux, the
   routing sysctl that `arp -an` uses on macOS. Every host that answered ARP is in it with its MAC.
   Other platforms are not supported yet.
3. **Vendor.** The first half of the MAC (the OUI) is looked up in a copy of the IEEE registry built
   into the binary. Phones and laptops often use a randomized ("private") MAC, which names no vendor;
   the UI shows those as *Private address*.
4. **Names, from mDNS.** The hub asks the mDNS group (224.0.0.251) for the reverse name of every
   address found and browses a few common service types, as "legacy unicast" queries from an
   ordinary port: hosts running avahi or Bonjour (Raspberry Pi OS, macOS, iOS, most printers and
   TVs) answer with their `.local` name. The hub needs neither port 5353 nor any privilege, and does
   not answer mDNS itself.
5. **Names, from reverse DNS.** Hosts mDNS did not name are looked up with reverse DNS, only against
   a nameserver in `/etc/resolv.conf` with a private or link-local address (usually your router or
   Pi-hole). If the hub uses only public or loopback resolvers, this step is skipped, so no lookup
   leaves the LAN.

Hosts are stored by MAC address. A host that moves to another IP stays one entry with the new IP;
a name or vendor a later scan cannot find is kept from earlier scans. A host whose MAC is one of an
enrolled device's interfaces is that device, and is not listed as unmanaged.

To add names from your Pi-hole or DHCP server, and hosts on VLANs the sweep cannot reach, see
[Pi-hole and DHCP leases](pihole.md).

## Events

Each scan publishes, on the hub's event stream (`/api/v1/events`):

- `network.device.new` for a host no scan had found before;
- `network.device.returned` for a known host that no scan had found for an hour or more.

The first scan on an empty database is the baseline: it records every host and publishes nothing,
so turning discovery on does not report the whole LAN as new.

## New-device alerts

"Something new joined my network" as a phone notification. Configure a
[notification channel](notifications.md), then name it:

```sh
hearth hub --discover-subnet auto --new-device-alerts phone
# or HEARTH_NEW_DEVICE_ALERTS=phone
```

The hub then runs a built-in automation, `new-device-alerts`, that sends to that channel:

- **New device on your network** for every `network.device.new`: once per MAC address, at the
  first scan that finds it. A phone that joins the Wi-Fi and stays gets exactly one notification.
- **Device back on your network** for every `network.device.returned` of a host nobody has marked:
  one that no scan had found for an hour or more.

A scan that finds several hosts sends one notification for them, such as **12 new devices on your
network**, and another for the hosts that came back. It lists each host, at least 50 of them; on a
larger scan it ends with `and N more`, and the title still counts them all. The rest are on the
Devices page.

Without the flag the automation is off. The hub refuses to start if the channel is not in the
channels file, and warns if discovery is off. Hosts that are one of an enrolled device's interfaces
never alert: they are that device.

**Silencing a host.** On the Devices page, **On your network** has a **Known** and an **Ignore**
button on each host. Both stop its alerts: *known* is a host you recognise as yours, *ignored* one
you do not care about (a neighbour's TV), shown dimmed. **Unmark** turns its alerts back on. A host
nobody has marked notifies again each time it comes back after an hour or more away, so a phone
that leaves the house every day should be marked known after its first alert.

**Randomized ("private") MACs.** A phone with a private Wi-Fi address shows as *private address* in
the notification. iOS and Android keep one such address per network by default, so a phone still
alerts once. A phone set to rotate its address (iOS "Rotating", Android "non-persistent") is a new
host to discovery after every rotation, and alerts again each time: discovery knows hosts only by
MAC, and a mark on one address does not carry over to the next.

**Changing it.** To change the message, the channel, or to alert on new hosts only, write your own
automation with the id `new-device-alerts` in the automations directory: it replaces the built-in.
The `network` trigger is in the [automation reference](automations.md#network-hosts). Give its
triggers `batch: true`: without it a scan fires once per host, and hosts past the 11 runs an
automation can hold at a time are dropped.

**If a notification fails.** It is not sent again. The run shows as `failed` in
`hearth automation runs`, with the hosts in its trigger step, and the audit log has the failure. The
hosts stay unmarked on the Devices page, and later scans alert as usual.

In a cluster, the automation runs on the leader: give every hub the same `--new-device-alerts`.

## Policy and audit

A scan is the hub action `network.scan` (class `read`, actor `hub/discovery`). Each scan is one
audit entry whatever the number of hosts, with the subnets as target and the counts (hosts, new,
returned, duration) in its detail. A policy that denies the `read` class stops scanning.

## In a cluster

Only the leader scans; the results are replicated to every hub through Raft (one log entry per scan).
Set the discovery flags on every hub, so the new leader keeps scanning after a failover. The scan
needs schema 12: run `hearth cluster migrate` after upgrading every hub.

## In a container

The sweep only reaches the network the hub's network namespace is attached to. In Docker's default
bridge network the hub sees the bridge, not your LAN, so run it with host networking:

```sh
docker run -d --name hearth --network host -v hearth:/var/lib/hearth \
  ghcr.io/gvart/hearth hub --discover-subnet 192.168.1.0/24
```

No extra capability is needed: discovery opens no raw socket, so `NET_RAW` and `NET_ADMIN` can stay
dropped. In Kubernetes, the same applies: `hostNetwork: true` on the hub's pod.

## API

`GET /api/v1/network/hosts` (behind the admin session) returns every host found:

```json
{"hosts": [{"mac": "2c:cf:67:12:34:56", "ip": "192.168.1.171", "hostname": "pi5.local",
  "vendor": "Raspberry Pi", "device_id": "", "first_seen": "...", "last_seen": "..."}]}
```

`device_id` is the enrolled device with that MAC, or empty for an unmanaged host. `state` is `""`,
`"known"` or `"ignored"`. Each host also has `sources` (`scan`, `pihole`, `dhcp`) and
`hostname_source`; see [Pi-hole and DHCP leases](pihole.md#api).

```
POST /api/v1/network/hosts/{mac}/known    204, or 404 no such host
POST /api/v1/network/hosts/{mac}/ignore
POST /api/v1/network/hosts/{mac}/unmark
```

Each one is the action `network.host.mark` (class `safe`, actor `web`), audited with the MAC as
target and the new state as detail. In a cluster marking needs schema 13: run
`hearth cluster migrate` after upgrading every hub (until then it answers 409).
