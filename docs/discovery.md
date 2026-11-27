---
title: Network discovery
description: See every host on the LAN, not only the devices with an agent.
---

Network discovery finds the hosts on your LAN that have no agent (the router, a printer, a TV, a
phone) and lists them under **On your network** on the Devices page, with their IP, MAC address,
vendor and name. Each one has an **Add device** button that opens the usual
[install-and-join flow](getting-started.md) for that host: the device name is prefilled from its
hostname (without `.local`), and the device joins under that name. Change it under
**Name, expiry and labels**, then click **New token with these options**. A host that cannot run
an agent can be [adopted](#adopting-a-host) as a device instead.

The hub scans only when you ask it to, with **Scan my network** (see [Scan now](#scan-now)), or on a
schedule once you turn that on. Nothing it learns leaves your LAN.

## Scan now

**Scan my network**, in the head of the Devices page and in its empty state, scans once: the subnets
of `--discover-subnet` or, when there are none, the hub's own LANs (each private IPv4 subnet,
narrowed to its /24, as `auto` does). The button reads **Scanning…** until the scan ends, then the
page says what it found ("Found 14 hosts, 3 new") and **On your network** lists the hosts. The same
from a terminal, with the admin password from `HEARTH_ADMIN_PASSWORD` or asked for:

```sh
hearth network scan [--hub-url http://hub.lan:8080]
# Scanning the network…
# Found 14 hosts: 3 new, 0 back (5.1s)
```

One scan by a hub runs at a time, scheduled or asked for: asking while one runs is refused (409).
In a cluster, the scan runs on the master that served the request. It sweeps from the hub only: the
subnets configured for a device (`CIDR@device`) are left to the schedule.

## Scan on a schedule

```sh
hearth hub --discover-subnet 192.168.1.0/24
# or the hub's own LANs (each private IPv4 subnet, narrowed to its /24)
hearth hub --discover-subnet auto
# or
HEARTH_DISCOVER_SUBNETS=192.168.1.0/24,192.168.20.0/24 hearth hub
```

| Flag | Env | Default | |
| --- | --- | --- | --- |
| `--discover-subnet` | `HEARTH_DISCOVER_SUBNETS` (comma-separated) | off | IPv4 CIDR, or `auto`; repeatable. Turns on scheduled scans |
| `--discover-interval` | `HEARTH_DISCOVER_INTERVAL` | `5m` | Time between scans |

The hub scans once at start and then every interval. A scan of a /24 takes about 5 seconds. Subnets
must be IPv4, at most 1024 addresses in all (a /22), and directly attached to the hub: the sweep sees
only hosts on the hub's own layer-2 network, not hosts behind a router. For a subnet the hub is not
on, have a device that is on it [scan it](#scan-from-a-device).

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
   TVs) answer with their `.local` name, and with the services they offer (`_ipp._tcp`,
   `_airplay._tcp`, `_ssh._tcp`, ...), which tell what [kind](#kinds) of host each is. The hub needs
   neither port 5353 nor any privilege for this. (Separately, one master answers mDNS for
   `hearth.local`, the [web UI's LAN name](cluster.md#the-ui-on-any-master).)
5. **Names, from reverse DNS.** Hosts mDNS did not name are looked up with reverse DNS, only against
   a nameserver in `/etc/resolv.conf` with a private or link-local address (usually your router or
   Pi-hole). If the hub uses only public or loopback resolvers, this step is skipped, so no lookup
   leaves the LAN.
6. **Gateway.** The hub reads its own IPv4 default gateways from the routing table
   (`/proc/net/route` on Linux, the routing sysctl on macOS; none on other platforms) and flags the
   host with that address's MAC. A later scan that flags another host in the same subnet unflags
   the old one; a scan that flags none (a device's, or one that could not read the table) changes
   no flag.

Hosts are stored by MAC address. A host that moves to another IP stays one entry with the new IP;
a name, vendor or set of services a later scan cannot find is kept from earlier scans. A host whose
MAC is one of an enrolled device's interfaces is that device, and is not listed as unmanaged.

## Kinds

Each host gets a kind, worked out whenever it is listed from what discovery knows of it: its mDNS
services, its vendor, its hostname and whether it is the gateway. On the Devices page the kind is a
small mark and a word under the host's name; hover it for the services the host announced.

| Kind       | What it is                                        |
| ---------- | ------------------------------------------------- |
| `router`   | the gateway, or other network gear (switch, AP)   |
| `printer`  | a printer or scanner                              |
| `media`    | a TV, streamer, speaker or console                |
| `phone`    | a phone or tablet                                 |
| `computer` | a desktop, laptop, server, Raspberry Pi or VM     |
| `nas`      | network storage                                   |
| `iot`      | a smart plug, bulb, sensor, camera or ESP board   |
| `unknown`  | nothing gives it away                             |

The first rule that matches decides:

1. **The gateway** is a `router`.
2. **A print service** (`_ipp._tcp`, `_ipps._tcp`, `_printer._tcp`, `_pdl-datastream._tcp`,
   `_uscan._tcp`) makes a `printer`.
3. **A telling hostname**, its host part only (`anna-7` of `anna-7.fritz.box`), tried in this
   order: `printer` (`printer`, `laserjet`), `nas` (`synology`, `truenas`, `nas`), `media`
   (`appletv`, `chromecast`, `playstation`, `nintendo`, `ps4`, `tv`), `router` (`router`,
   `openwrt`, `fritz`, `unifi`), `phone` (`iphone`, `ipad`, `android`, `pixel`, `galaxy`),
   `computer` (`macbook`, `imac`, `thinkpad`, `desktop`, `raspberrypi`, `mac`, `pc`, `server`), `iot`
   (`esphome`, `shelly`, `tasmota`, `cam`, `plug`). Short words count only as a whole word of the
   name, so `pixelbook` is not a phone.
4. **A vendor that makes one sort of thing**, in whole words (Intel, not Intelbras): Brother, Epson
   or Canon a `printer`; Synology or QNAP a `nas`; Ubiquiti, MikroTik (Routerboard), AVM, Arcadyan
   or Netgear a `router`; OnePlus or Fairphone a `phone`; Sonos, Roku, Amazon or Nintendo `media`;
   Espressif, Tuya, Shelly or Signify (Hue) `iot`; Raspberry Pi, Intel, Dell, Lenovo, VMware or
   Proxmox a `computer`.
5. **The services**: file shares (`_smb._tcp`, `_afpovertcp._tcp`, `_adisk._tcp`, `_nfs._tcp`)
   without a desktop's `_workstation._tcp` make a `nas`; a shell (`_ssh._tcp`, `_sftp-ssh._tcp`) or
   `_workstation._tcp` a `computer`; Cast, AirPlay, Spotify Connect or a sleep proxy `media`;
   ESPHome, HomeKit (`_hap._tcp`), Matter, Hue or Shelly `iot`; iOS pairing
   (`_apple-mobdev2._tcp`, `_remotepairing._tcp`) a `phone`.
6. Anything else is `unknown`.

A host announcing ESPHome's native API (`_esphomelib._tcp`) also gets an **Adopt ESPHome** action, which
reads its sensors and switches with its encryption key: see [ESPHome](esphome.md).

Each host also gets `agent_capable`: true for a `computer`, and for anything offering a shell or
announcing itself as a workstation (a NAS or router with SSH on, say). It is a hint for where an
agent could go, not a promise.

The order settles the usual ambiguities, and leaves some:

- **A Mac answers for AirPlay**, as an Apple TV does: a Mac whose name does not say so (not
  `MacBook-…`, `iMac-…`) is `media`.
- **Apple, Samsung, Google, HP, TP-Link and Ring** make many kinds, so their name alone decides
  nothing: such a host is classified by its name and services, or is `unknown`.
- **A NAS offers SSH like a computer does**: a known NAS vendor wins over the services, but a
  home-built NAS on an Intel board is a `computer`.
- **Randomized MACs** name no vendor: a quiet phone or laptop on a private address is `unknown`.
- **A device's scan** sends names, not services or gateways, so hosts on its subnets are classified
  from their vendor and name only.

To add names from your Pi-hole or DHCP server, and hosts on VLANs the sweep cannot reach, see
[Pi-hole and DHCP leases](pihole.md). An adopted [OpenWrt](openwrt.md) router adds its clients the same way, from
its DHCP leases.

## Adopting a host

A printer, a TV or the router cannot run an agent, but it is still one of your devices. **Adopt**,
on a host under **On your network**, asks for a name (prefilled with the host's name) and moves the
host to **Network devices** on the Devices page: its name, kind, IP, vendor, when a scan last saw it
and whether it is online. Nothing is installed or enrolled, and there is nothing to control: an
adopted host has no certificate, no agent and no actions. **Unadopt** puts it back under **On your
network**, unmarked, and forgets the name. Adopting an adopted host renames it.

The same from a terminal:

```sh
hearth network hosts
# MAC                IP             NAME            KIND     STATE    ONLINE
# 00:11:32:12:34:56  192.168.1.20   Living room TV  media    adopted  yes
# 00:80:77:12:34:56  192.168.1.40   brother         printer  -        yes
hearth network adopt 00:80:77:12:34:56 --name "Office printer"
hearth network unadopt 00:80:77:12:34:56
```

A name is 1 to 63 characters, leading and trailing spaces trimmed, with no control characters. A
host that is one of an enrolled device's interfaces is that device, and cannot be adopted (409).

**Online** means a scan (or an import, see [Pi-hole and DHCP leases](pihole.md)) saw the host
within twice the discover interval: 10 minutes with the default `--discover-interval 5m`. Without
a schedule (no `--discover-subnet`), it is twice the default interval after the last
**Scan my network**. A host that sleeps (a TV in standby, a printer off) and does not answer the
sweep shows as offline.

An adopted host fires no new-device alerts, as a known one does (see
[New-device alerts](#new-device-alerts)). Marking it known or ignored ends the adoption.

## Scan from a device

A VLAN, another site, or a LAN the hub cannot reach from its container: the hub's sweep cannot see
it, but an enrolled device on that network can. Name the device after the subnet, and its agent runs
the same scan (ARP sweep, mDNS, LAN reverse DNS) there and sends the hosts it found to the hub:

```sh
# let the hub sweep that subnet from the device nas (Network scan in its Capabilities card, or:)
hearth device capabilities <device-id> --set scan=10.0.5.0/24
# on the hub: the LAN from the hub itself, the VLAN from the device named nas
hearth hub --discover-subnet 192.168.1.0/24 --discover-subnet 10.0.5.0/24@nas
```

`CIDR@device` names the device by id, name or hostname. Each subnet has one scanner, the hub or a
device; a device's subnets are limited to 1024 addresses, as the hub's are.

**The device has the last word.** Scanning is off on every agent until its
[capability ceiling](guardrails.md#device-capability-ceiling) names a subnet: **Network scan** in its
Capabilities card (on is the private ranges, or **Restrict to…** some), or the agent's own
`--allow-scan` flag (repeatable). A scan is sent only if each of its subnets lies within one the
agent allows: `10.0.0.0/16` allows `10.0.5.0/24`, `10.0.5.0/25` does not. The hub checks
the ceiling the agent reported before sending, and the agent checks again before it sends a single
datagram. A scan beyond the ceiling is denied and audited, like any other action beyond it.
The agent takes any IPv4 CIDR, `--allow-scan 0.0.0.0/0` included, which lets the hub choose any
subnet from that device; each scan is still capped at 1024 addresses.

The agent needs no privilege either, and runs one scan at a time. It does not load the vendor
table: the hub names each host's vendor from its MAC. Nothing of a scan stays in the agent's memory
once it is done. The hub checks what the agent sends back: hosts outside the subnets, broken MACs
and repeats are dropped. A device's scan never moves a known host whose last IP is outside the
subnets it scanned, so an agent cannot claim another network's MAC, such as the router's; only a
scan of that host's own subnet updates it.

The hub runs its own scan and each device's at the same time, so one slow agent delays no other
scan. A device that is unknown, or whose agent is not connected to the hub, is skipped with a line
in the hub log and no audit entry: nothing was sent.

On the Devices page each host a device found shows **Scanned by** that device in its Source column.
Each subnet has its own baseline, whoever scans it: a device's first scan of a VLAN does not
report its hosts as new. A host found by both the hub and a device shows the scanner that found it
last.

## Events

Each scan publishes, on the hub's event stream (`/api/v1/events`):

- `network.device.new` for a host no scan had found before;
- `network.device.returned` for a known host that no scan had found for an hour or more.

A scan asked for with **Scan my network** or `hearth network scan` also ends with
`network.scan.done`, with the id the scan was started with: `{"type": "network.scan.done",
"id": "…", "hosts": 14, "new": 3, "returned": 0, "duration_ms": 5120}`, or `{"type": "network.scan.done", ..., "error": "..."}` if it failed.

Each configured subnet has its own baseline: until a scan has found a host in it, the hosts found
there are recorded and nothing is published, so turning discovery on, or adding a subnet next to
known ones, does not report the whole new subnet as new.

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
[Adopted](#adopting-a-host) hosts are silent too.

**Randomized ("private") MACs.** A phone with a private Wi-Fi address shows as *private address* in
the notification. iOS and Android keep one such address per network by default, so a phone still
alerts once. A phone set to rotate its address (iOS "Rotating", Android "non-persistent") is a new
host to discovery after every rotation, and alerts again each time: discovery knows hosts only by
MAC, and a mark on one address does not carry over to the next.

**Changing it.** To change the message, the channel, or to alert on new hosts only, write your own
automation with the id `new-device-alerts`: it replaces the built-in.
The `network` trigger is in the [automation reference](automations.md#network-hosts). Give its
triggers `batch: true`: without it a scan fires once per host, and hosts past the 11 runs an
automation can hold at a time are dropped.

**If a notification fails.** It is not sent again. The run shows as `failed` in
`hearth automation runs`, with the hosts in its trigger step, and the audit log has the failure. The
hosts stay unmarked on the Devices page, and later scans alert as usual.

In a cluster, the automation fires on the master that ran the scan: give every master the same
`--new-device-alerts`.

## Policy and audit

A scan is the hub action `network.scan` (class `read`), with the actor `hub/discovery` on the
schedule and `web/<client address>` when asked for from the web UI or the CLI. Each scan is one
audit entry whatever the number of hosts, with the subnets as target and the counts (hosts, new,
returned, duration) in its detail. A policy that denies the `read` class stops scanning; one that
denies it to the `web` actor only refuses **Scan my network** (403), and audits the denial.

Each device's scan is a scan of its own, with `from` (the device as configured) and `device_id` in
its detail. A scan its ceiling does not allow is a `deny` entry naming the subnet beyond it; one its
agent refuses, fails or does not answer in time is an `allow` entry whose result is the error. A
device that is unknown or not connected is skipped without an entry (see above).

## In a cluster

One master scans, and the results are replicated to the cluster. Set the discovery flags on every
master, so that another one takes the scans over when that master goes away. A scan from a device is
forwarded to the master its agent streams to.

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
  "vendor": "Raspberry Pi", "device_id": "", "first_seen": "...", "last_seen": "...",
  "services": ["_ssh._tcp", "_workstation._tcp"], "kind": "computer", "agent_capable": true}]}
```

`kind` and `agent_capable` are described in [Kinds](#kinds); `services` are the mDNS service types
the host answers for, sorted (`[]` when none was heard).
`device_id` is the enrolled device with that MAC, or empty for an unmanaged host. `scanned_by` is
the device whose agent last found it in a scan, or empty when the hub did. `state` is `""`,
`"known"`, `"ignored"` or `"adopted"`, and `name` the name an adopted host was given (empty
otherwise). `online` is whether a scan or an import saw it within twice the discover interval (see
[Adopting a host](#adopting-a-host)). Each host also has `sources` (`scan`, `pihole`, `dhcp`) and
`hostname_source`; see [Pi-hole and DHCP leases](pihole.md#api).

```
POST /api/v1/network/hosts/{mac}/known    204, or 404 no such host
POST /api/v1/network/hosts/{mac}/ignore
POST /api/v1/network/hosts/{mac}/unmark
```

Each one is the action `network.host.mark` (class `safe`, actor `web`), audited with the MAC as
target and the new state as detail. Marking an adopted host ends its adoption.

```
POST /api/v1/network/hosts/{mac}/adopt {"name": "Living room TV"}
     204; 400 bad name; 404 no such host; 409 enrolled (an enrolled device's interface)
POST /api/v1/network/hosts/{mac}/unadopt
     204 (also for a host that is not adopted: it is left as it is); 404 no such host
```

Both are the action `network.host.adopt` (class `safe`, actor `web`, also from `hearth network
adopt` and `unadopt`, which use the web session), audited with the MAC as target and
`{"op": "adopt", "name": "…"}` or `{"op": "unadopt"}` as detail. A policy that denies it refuses
with 403 and audits the denial.

```
POST /api/v1/network/scan    202 {"id": "…"}; 409 scan_running, or no_subnet; 403 denied by policy
```

It starts one scan (see [Scan now](#scan-now)) and answers once policy has allowed it; the scan ends
with a `network.scan.done` event carrying the same `id`.
