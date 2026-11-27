---
title: OPNsense
description: Connect OPNsense firewalls through their REST API, see their DHCP leases, ARP table, interface traffic, system info and firmware status, feed their clients to discovery, and restart Unbound through policy.
---

Hearth reads the OPNsense firewalls you already run through their REST API, with an API key, over
https. Nothing is installed on the firewall. Hearth reads its system info and firmware status, its DHCP
leases (ISC DHCP, Kea and Dnsmasq), its ARP and NDP tables and its interfaces' traffic counters, and
feeds the clients to [network discovery](discovery.md). The one thing it changes is restarting Unbound,
the DNS resolver, and only when you ask, with your password, through policy.

> **Not yet tested on a real firewall.** This integration has been tested against a fake firewall
> written from the sources of OPNsense core (the API controllers, their configd scripts and the ACLs)
> and of its os-isc-dhcp plugin. It has not been run against a real OPNsense yet. It is written
> for OPNsense 25.7 or later: the first release whose privileges match the API paths it uses (with an
> older release, a key with limited privileges may be refused).

OpenWrt routers are covered in [OpenWrt](openwrt.md); UniFi is tracked in [#365](https://github.com/gvart/hearth/issues/365).

## Give Hearth a user and key of its own

An API key carries the privileges of its user. A key of `root` can do anything on the firewall, so
prefer a user that can read only what Hearth shows. In the web GUI:

1. **System → Access → Users → Add**: a user such as `hearth`, with a long random password (it is never
   used to log in) and **Login shell** none.
2. Under **Effective Privileges**, give it:

   | Privilege                                  | For                                     |
   | ------------------------------------------ | --------------------------------------- |
   | Lobby: Dashboard                           | system info, uptime, load and memory (required) |
   | Reporting: Traffic                         | the interfaces' traffic counters         |
   | Diagnostics: ARP Table                     | the ARP table                           |
   | Diagnostics: NDP Table                     | the NDP table (IPv6 neighbors)          |
   | Services: Dnsmasq DNS/DHCP: Settings       | Dnsmasq's DHCP leases                   |
   | Services: DHCP: Kea(v4)                    | Kea's DHCP leases                       |
   | Services: ISC DHCPv4: Leases               | ISC DHCP's leases (the os-isc-dhcp plugin) |
   | System: Firmware                           | the firmware status (optional)          |
   | Services: Unbound                          | restarting Unbound (optional)           |

   Give the lease privilege of only the DHCP server you run. Leave out **System: Firmware** and
   **Services: Unbound** for a firewall Hearth only reads: both privileges also allow changes (firmware
   updates, Unbound's settings), which Hearth never makes. Without the Unbound privilege,
   **Restart Unbound** is refused by the firewall itself, whatever Hearth's policy says: the key's
   privileges are the ceiling.
3. Save, then under **API keys** press **+**. The browser downloads a file with the `key` and `secret`.

A privilege the key lacks does not make the firewall unavailable: the page lists what it could not read,
and why. Each refused request is also logged by the firewall, every 15 seconds.

## Connect it

**Platforms → Connect platform → OPNsense firewall**:

| Field       | What to give                                                                     |
| ----------- | -------------------------------------------------------------------------------- |
| Name        | How Hearth names the firewall. Unique on the hub.                                |
| Firewall URL| `https://192.168.1.1`, with `:port` if the web GUI is not on 443.                |
| API key     | The `key` of the file.                                                           |
| API secret  | Its `secret`.                                                                    |
| Fingerprint | For the firewall's self-signed certificate: its SHA-256, `AA:BB:…`.               |

The URL must be https: every request carries the key and secret. Hearth always verifies the certificate,
against the system's roots or against the fingerprint you pin. OPNsense's web GUI uses a self-signed
certificate unless you gave it another, so pin it: get the fingerprint from **System → Trust →
Certificates** (the web GUI's certificate, **Info**), or from a shell with
`openssl s_client -connect 192.168.1.1:443 </dev/null | openssl x509 -noout -fingerprint -sha256`.

The key and secret are sealed (AES-256-GCM, under a key of their own derived from the hub CA key) before
they reach the database, and are re-sealed when the hub CA is rotated. They are never logged, served by
the API or written to the audit log, and never shown again: to change them, remove the firewall and
connect it again.

## What Hearth shows

The firewall's page (**Platforms → the firewall**), read every 15 seconds:

- **System**: hostname, version and firmware status (as of the firewall's last update check: Hearth never
  starts one), uptime, load and memory.
- **Clients**: one row per MAC, merged from the DHCP leases (IP, hostname, the server, time left on the
  lease), the ARP table (whether the host is there now, its vendor) and the NDP table (its IPv6
  addresses). A host with a static address shows from the ARP table alone. The firewall's own interfaces
  are left out.
- **Interfaces**: each assigned interface, with its bytes received and sent and its errors since boot.

Hearth reads the leases of all three DHCP servers OPNsense has: Dnsmasq (the default of new installs),
Kea, and ISC DHCP (on current releases, the os-isc-dhcp plugin). As long as one of them is read, a server whose
privilege the key lacks or that is not installed is not listed as missing.

Every master of a [cluster](cluster.md) reads every firewall itself.

## Discovery

The clients with an IPv4 address feed network discovery like a Pi-hole does: under **On your network**
their hostnames come from the firewall's leases (the name the client sent), a host in the ARP table
counts as seen, and **OPNsense** is listed among where each host was learned. IPv6 addresses stay on the
firewall's page. The import runs every discovery interval and is audited as `network.import`; while no
firewall is read, nothing is imported.

## Restart Unbound

**Restart Unbound** on the firewall's page restarts the firewall's DNS resolver
(`POST /api/unbound/service/restart`). For a moment no device can resolve names, Unbound's cache is
emptied, and a broken configuration keeps it down, so it is a **dangerous** action
(`opnsense.unbound.restart`): the web UI asks for the admin password again, policy decides, and the audit
log keeps the decision. Only a signed-in admin of the web UI can ask for it: automations, MCP clients and
agents cannot.

## Security

| Action                     | Class     | Who                             |
| -------------------------- | --------- | ------------------------------- |
| `opnsense.firewall.add`    | safe      | web UI                          |
| `opnsense.firewall.remove` | safe      | web UI                          |
| `opnsense.unbound.restart` | dangerous | web UI, with the password again |

See [Guardrails](guardrails.md) to deny or hold them for approval.
