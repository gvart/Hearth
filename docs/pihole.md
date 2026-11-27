---
title: Pi-hole and DHCP leases
description: Names and hosts from your Pi-hole or DHCP server, on every VLAN.
---

Your Pi-hole or DHCP server already knows the hosts on your network by name, on every VLAN it
serves. The hub can import that list and merge it with what [network discovery](discovery.md)
finds. Hosts on another VLAN, which the ARP sweep cannot reach, then appear under **On your
network** too, and the names you gave hosts in Pi-hole replace the ones mDNS found. Hearth only
reads: it changes nothing in Pi-hole or in the lease files.

Import works with or without `--discover-subnet`.

## Pi-hole

Hearth supports Pi-hole v6 and reads its REST API (`/api`). Pi-hole v5 (`admin/api.php`) is not
supported: v5 is end of life, and its API cannot list DHCP leases.

1. In the Pi-hole web interface, open **Settings → Web interface / API → Advanced settings** and
   choose **Configure app password**. Copy the password and save it. Pi-hole shows it only once.
   An app password works even with two-factor authentication on.
2. Give the password to the hub through the environment, or through a file only the hub's user can
   read. Never put it on the command line, where every user on the host can see it in `ps`.

```sh
HEARTH_PIHOLE_PASSWORD='...' hearth hub --pihole-url http://pi.hole
# or
install -m 600 /dev/null /etc/hearth/pihole.pass   # then write the password into it
hearth hub --pihole-url http://pi.hole --pihole-password-file /etc/hearth/pihole.pass
```

| Flag | Env | |
| --- | --- | --- |
| `--pihole-url` | `HEARTH_PIHOLE_URL` | The Pi-hole web server, e.g. `http://pi.hole` or `http://192.168.1.2:8080` |
| | `HEARTH_PIHOLE_PASSWORD` | The app password |
| `--pihole-password-file` | `HEARTH_PIHOLE_PASSWORD_FILE` | A file holding it. The hub refuses a file that group or others can read |

If your Pi-hole has no password, leave the password out.

Use `http://` on your LAN. Pi-hole v6 serves HTTPS with a self-signed certificate that the hub
cannot verify, and Hearth has no option to skip verification. With your own certificate on the
Pi-hole, `https://` works.

On each import the hub logs in, reads two endpoints, and logs out:

- `GET /api/network/devices`, Pi-hole's network table: every client that sent it DNS queries or
  sat in its ARP cache, with MAC, addresses and the names Pi-hole resolved. Entries Pi-hole has
  not seen for 30 days are skipped. Pi-hole keeps them for a year.
- `GET /api/dhcp/leases`, its active DHCP leases, if Pi-hole is your DHCP server.

Logging out each time frees the API session, so the hub never holds one of Pi-hole's limited API
seats. The password and the session ID are never logged.

## DHCP lease files

If the hub runs on your DHCP server, or can read its lease file, point it at the file:

```sh
hearth hub --dhcp-leases /var/lib/misc/dnsmasq.leases
hearth hub --dhcp-leases /var/lib/dhcp/dhcpd.leases --dhcp-leases /srv/vlan20/dnsmasq.leases
# or
HEARTH_DHCP_LEASES=/var/lib/misc/dnsmasq.leases hearth hub
```

| Flag | Env | |
| --- | --- | --- |
| `--dhcp-leases` | `HEARTH_DHCP_LEASES` (comma-separated) | A lease file; repeatable |

The hub reads two formats and tells them apart by content:

- **dnsmasq**, which is what OpenWrt, Pi-hole v5 and many routers use (`/var/lib/misc/dnsmasq.leases`,
  `/tmp/dhcp.leases` on OpenWrt). IPv4 leases that have not expired are imported.
- **ISC dhcpd** (`dhcpd.leases`). The last entry for each address wins. Leases that are not
  `binding state active` or that have ended are skipped.

The file must exist when the hub starts. It is read again on every import.

## How hosts are merged

Imports run once at start and then every `--discover-interval` (default 5 minutes). Each import
reads every source and records the result as one write. A source that fails, for example a
Pi-hole that is down or a wrong password, is logged and skipped, and the other sources are still
imported.

Hosts are matched by MAC address with the hosts discovery found:

- **Names.** A DHCP lease's name wins, because the client sent it or you pinned it on the server.
  Next comes a name from Pi-hole's network table, then the name a scan found through mDNS or
  reverse DNS. A later scan never replaces a name that Pi-hole or a lease gave. If an import finds
  no name, the stored one is kept.
- **New hosts.** A MAC no scan has seen, for example on another VLAN, becomes a network host with
  the lease's IP.
- **IP and last seen.** Pi-hole's network table and ISC leases say when they last saw a host, and
  the hub uses that time. dnsmasq leases and Pi-hole's lease list give only an expiry. A lease that
  has not expired says nothing about whether the device is on right now. So these leases add the
  host and its name, but they do not change a known host's IP or *Last seen*. A host known only from
  such a lease keeps the *Last seen* of its first import.
- **Source.** Each host lists where it was learned: `scan`, `pihole`, `dhcp`, `netalertx` (see [NetAlertX](netalertx.md)), `openwrt` (see [OpenWrt](openwrt.md)), `opnsense` (see [OPNsense](opnsense.md)). The **On your
  network** table shows these as badges.

Imports publish no events, and [new-device alerts](discovery.md#new-device-alerts) and the `network`
automation trigger follow scans only:

- A host an import added is still `network.device.new` to the first [scan](discovery.md#events) that
  finds it, and alerts then, under its Pi-hole name.
- A host only an import knows, for example on a VLAN the hub does not scan, never fires the event
  and never alerts.
- An import before the first scan does not end the baseline, so that scan reports nothing as new.
- A host counts as returned when no *scan* found it for an hour or more, even if Pi-hole saw it in
  the meantime.
- **Known** and **Ignore** work on imported hosts too, and an import never changes the mark.

## Policy and audit

An import is the hub action `network.import` (class `read`, actor `hub/discovery`). It is one audit
entry per import, with the sources as target (`pihole:http://pi.hole`, `dhcp:/path`) and the host
count, the duration and any failed source in its detail. A policy that denies the `read` class
stops imports.

## In a cluster

One master imports, and the result is replicated to the cluster. Set the flags, and give the password
and lease files, on every master, so that another one takes the import over when that master goes
away.

## API

`GET /api/v1/network/hosts` gives each host's `sources` and the `hostname_source` its name came
from:

```json
{"hosts": [{"mac": "2c:cf:67:12:34:56", "ip": "192.168.1.171", "hostname": "pi5",
  "vendor": "Raspberry Pi", "device_id": "", "first_seen": "...", "last_seen": "...",
  "sources": ["pihole", "scan"], "hostname_source": "pihole"}]}
```
