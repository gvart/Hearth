---
title: OpenWrt
description: Connect OpenWrt routers through ubus, see their clients, interface traffic and system info, feed their DHCP leases to discovery, and restart dnsmasq through policy.
---

Hearth reads the OpenWrt routers you already run through ubus, the API LuCI itself uses, over the
router's web server (`/ubus`). Nothing is installed on the router beyond what LuCI brings. Hearth reads
its system info, its interfaces' traffic counters and its clients (DHCP leases and Wi-Fi associations),
and feeds the clients to [network discovery](discovery.md). The one thing it changes is restarting
dnsmasq, and only when you ask, with your password, through policy.

> **Not yet tested on a real router.** This integration has been tested against a fake router written
> from the sources of uhttpd, rpcd, procd, netifd and LuCI's rpcd module. It has not been run against a
> real OpenWrt yet.

OPNsense firewalls are covered in [OPNsense](opnsense.md); UniFi ([#365](https://github.com/gvart/hearth/issues/365)) is tracked separately.

## What the router needs

A router with LuCI has everything. Without LuCI, install:

| Package            | For                                               |
| ------------------ | ------------------------------------------------- |
| `uhttpd-mod-ubus`  | `/ubus` on the web server                          |
| `rpcd`             | the session login, and system info                |
| `rpcd-mod-luci`    | the DHCP leases (`luci-rpc getDHCPLeases`)         |
| `rpcd-mod-iwinfo`  | the Wi-Fi clients (`iwinfo assoclist`)            |
| `rpcd-mod-rc`      | restarting dnsmasq (`rc init`)                     |

A missing package does not make the router unavailable: the page lists what it could not read, and why.

## Give Hearth a login of its own

`root` works, but it can do anything on the router. Prefer a login that can read only what Hearth
shows. On the router, create the ACL `/usr/share/rpcd/acl.d/hearth.json`:

```json
{
  "hearth": {
    "description": "Hearth: read clients, interfaces and system info; restart dnsmasq",
    "read": {
      "ubus": {
        "system": ["board", "info"],
        "network.device": ["status"],
        "luci-rpc": ["getDHCPLeases"],
        "iwinfo": ["devices", "assoclist"]
      }
    },
    "write": {
      "ubus": { "rc": ["init"] }
    }
  }
}
```

Then the login, in `/etc/config/rpcd`, with a password hash from `uhttpd -m 'the password'`:

```
config login
	option username 'hearth'
	option password '$1$…'   # what uhttpd -m printed
	list read 'hearth'
	list write 'hearth'     # leave this out for a router Hearth only reads
```

and `service rpcd restart`. Without the `write` line, **Restart dnsmasq** is refused by the router
itself, whatever Hearth's policy says: the router's ACL is the ceiling.

## Connect it

**Platforms → Connect platform → OpenWrt router**:

| Field       | What to give                                                                        |
| ----------- | ----------------------------------------------------------------------------------- |
| Name        | How Hearth names the router. Unique on the hub.                                     |
| Router URL  | `https://192.168.1.1` or `http://192.168.1.1`, with `:port` if not the default.     |
| Username    | The rpcd login, such as `hearth` above.                                             |
| Password    | Its password.                                                                       |
| Fingerprint | For https with the router's self-signed certificate: its SHA-256, `AA:BB:…`.          |

Use https if the router serves it (`luci-ssl` installs it). Over plain http, the password and the
session cross your network in the clear. With https Hearth always verifies the certificate: against the
system's roots, or against the fingerprint you pin. Get the fingerprint on the router with
`openssl x509 -in /etc/uhttpd.crt -noout -fingerprint -sha256`. A router that redirects http to https
asks for the https URL.

The password is sealed (AES-256-GCM, under a key of its own derived from the hub CA key) before it
reaches the database, and is re-sealed when the hub CA is rotated. It and the session ID are never
logged, served by the API or written to the audit log, and never shown again: to change it, remove the
router and connect it again.

## What Hearth shows

The router's page (**Platforms → the router**), read every 15 seconds:

- **System**: model, OpenWrt release, uptime, load and memory.
- **Clients**: one row per MAC, merged from the DHCP leases (IP, hostname, time left on the lease) and
  the Wi-Fi associations (radio, signal). A client that is on Wi-Fi without a lease, such as one with a
  static IP, shows without an address.
- **Interfaces**: each network device but loopback, up or down, with its bytes received and sent and
  its errors since boot.

Hearth logs in once and keeps the session: rpcd extends it on each call. When the router no longer
knows the session (it restarted, or the session timed out) Hearth logs in again once; a call the login's
ACL does not allow is listed as not read instead of logging in over and over.

Every master of a [cluster](cluster.md) reads every router itself.

## Discovery

The clients with a DHCP lease feed network discovery like a Pi-hole does: under **On your network**
their hostnames come from the router's leases (the name the client sent), and **OpenWrt** is listed
among where each host was learned. The import runs every discovery interval and is audited as
`network.import`; while no router is read, nothing is imported.

## Restart dnsmasq

**Restart dnsmasq** on the router's page restarts the router's DNS and DHCP server (`rc init dnsmasq
restart`). For a moment no device can resolve names or renew a lease, and a broken configuration keeps
dnsmasq down, so it is a **dangerous** action (`openwrt.dnsmasq.restart`): the web UI asks for the admin
password again, policy decides, and the audit log keeps the decision. Only a signed-in admin of the web
UI can ask for it: automations, MCP clients and agents cannot.

## Security

| Action                    | Class     | Who          |
| ------------------------- | --------- | ------------ |
| `openwrt.router.add`      | safe      | web UI       |
| `openwrt.router.remove`   | safe      | web UI       |
| `openwrt.dnsmasq.restart` | dangerous | web UI, with the password again |

See [Guardrails](guardrails.md) to deny or hold them for approval.
