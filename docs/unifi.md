---
title: UniFi
description: Connect a UniFi Network controller (UniFi OS console or self-hosted), see its gateways, switches, access points, clients and WAN health, feed its clients to discovery, and restart an access point through policy.
---

Hearth reads the UniFi Network controller you already run: a UniFi OS console (Dream Machine, Cloud
Gateway, Cloud Key Gen2+, UniFi OS Server) or a self-hosted UniFi Network application. It reads one
site's devices (gateways, switches and access points), its clients (wired and wireless) and its health
(WAN, internet, LAN, Wi-Fi), and feeds the clients to [network discovery](discovery.md). Nothing is
installed on the controller. The one thing Hearth changes is restarting an access point, and only when
you ask, with your password, through policy.

> **Not yet tested on a real controller.** This integration has been tested against a fake controller
> written from the behaviour of maintained clients of the UniFi Network API. It has not been run against
> a real console or controller yet.

## Give Hearth an account of its own

Hearth signs in one of two ways:

- **An API key** (UniFi OS consoles, Network 9.0 and later): in the console, **Settings → Control Plane
  → Integrations → Create API key**. Hearth sends it as `X-API-KEY`.
- **A local username and password** (any controller): create a local admin, not a UI.com account, as
  two-factor sign-in cannot be automated. A **View Only** role is enough to read everything; restarting
  an access point needs a role that may manage devices (Site Admin). A role that cannot read something
  does not make the controller unavailable: the page lists what it could not read.

A self-hosted controller has no API keys: give it a local login.

## Connect it

**Platforms → Connect platform → UniFi controller**:

| Field          | What to give                                                                                   |
| -------------- | ---------------------------------------------------------------------------------------------- |
| Name           | How Hearth names the controller. Unique on the hub.                                            |
| Controller     | **UniFi OS console** or **Self-hosted UniFi Network application**.                             |
| Controller URL | `https://192.168.1.1` for a console, `https://unifi.lan:8443` for a self-hosted controller.     |
| Sign in with   | An API key, or a local username and password (a self-hosted controller takes only the latter). |
| Site           | The site's short name, as in the address bar's `/manage/site/<name>/`. `default` unless you have several. |
| Fingerprint    | The SHA-256 of the controller's certificate, `AA:BB:…`, for a self-signed one.                  |

UniFi serves its API over https only. Its certificate is self-signed unless you replaced it, so pin its
fingerprint: Hearth never turns verification off, and without a fingerprint it checks the certificate
against the system's roots. Get the fingerprint with

```
openssl s_client -connect 192.168.1.1:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

(port 8443 for a self-hosted controller), from a machine you trust to reach the real controller.

The API key or password is sealed (AES-256-GCM, under a key of its own derived from the hub CA key)
before it reaches the database, and is re-sealed when the hub CA is rotated. It, the session cookie and
the CSRF token are never logged, served by the API or written to the audit log, and never shown again:
to change them, remove the controller and connect it again.

## What Hearth shows

The controller's page (**Platforms → the controller**), read every 15 seconds:

- **Health**: each subsystem's status, with the WAN address, ISP and throughput, the internet latency,
  and the clients on the LAN and on Wi-Fi.
- **Devices**: gateways, then switches, then access points, with their model, firmware version, state
  (connected, disconnected, upgrading, …), clients and uptime.
- **Clients**: one row per connected client, with its name (the alias set in UniFi, or the hostname it
  sent), IP, vendor, and where it is connected: the access point and SSID with its signal, or the switch
  and port.

All of it comes from the Network application's `/api/s/<site>/` endpoints (`stat/health`,
`stat/device`, `stat/sta`), under `/proxy/network` on a console, with any sign-in. With a login,
Hearth keeps the session; when the controller no longer knows it (it restarted, or the session timed
out) Hearth logs in again once. An endpoint the account may not use (403) is listed as not read.

Every master of a [cluster](cluster.md) reads every controller itself.

## Discovery

The connected clients with an address feed network discovery like a Pi-hole does: under **On your
network** they are listed with their name and vendor, and **UniFi** among where each host was learned.
They are connected clients, not leases, so each also updates the host's IP and *Last seen* (when the
controller last heard of it). The import runs every discovery interval and is audited as
`network.import`; while no controller is read, nothing is imported.

## Restart an access point

**Restart** beside an access point on the controller's page restarts it (`cmd/devmgr restart`). Every
Wi-Fi client of that access point drops off for a minute or two, and one that does not come back
leaves its area without Wi-Fi, so it is a **dangerous** action (`unifi.ap.restart`): the web UI asks
for the admin password again, policy decides, and the audit log keeps the decision with the access
point's MAC. Only an access point the last read listed can be restarted, never a gateway or a switch.
Only a signed-in admin of the web UI can ask for it: automations, MCP clients and agents cannot. The
account's UniFi role is the ceiling: a View Only account is refused by the controller itself.

## Security

| Action                    | Class     | Who                             |
| ------------------------- | --------- | ------------------------------- |
| `unifi.controller.add`    | safe      | web UI                          |
| `unifi.controller.remove` | safe      | web UI                          |
| `unifi.ap.restart`        | dangerous | web UI, with the password again |

See [Guardrails](guardrails.md) to deny or hold them for approval.
