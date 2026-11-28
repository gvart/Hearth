---
title: Tailscale
description: Put the hub on your tailnet with --tailscale, to open the UI from a phone on cellular and to enroll agents over the tailnet, with no port forwarded.
---

`hearth hub --tailscale` puts the hub on your [Tailscale](https://tailscale.com) tailnet as a node
of its own. It uses [tsnet](https://tailscale.com/kb/1244/tsnet): the node runs inside the hub
process, with a userspace network stack. You don't need `tailscaled` on the host, and nothing
changes on its network: no TUN device, no routes, no DNS settings. Agents never start a node; only
the hub does.

You then get:

- **The UI from anywhere on the tailnet**, for example a phone on cellular, at
  `https://<name>.<tailnet>.ts.net/`. No port is forwarded and nothing is exposed to the internet.
- **Agents on the tailnet** can enroll and connect at `https://<name>.<tailnet>.ts.net:7443`, with
  the hub CA, the same as on the LAN.

The LAN listeners stay as they are. A hub on the tailnet still serves the LAN.

## Start the hub on the tailnet

1. In the Tailscale admin console, create an **auth key** (Settings → Keys → Generate auth key).
   It can be reusable or one-off. The hub's node is not ephemeral, so don't tick "Ephemeral". A
   **tagged** key (say `tag:hearth`) is best: a tagged node's key does not expire, and your ACLs can
   say who reaches the hub. Every node the ACLs let through can reach the hub's UI and agent ports.
   The login and mTLS still apply.
2. For a URL every browser trusts, turn on **MagicDNS** and **HTTPS certificates** (DNS page of the
   admin console). Without them it still works, on the hub CA's port (see below).
3. Start the hub with the key:

```sh
HEARTH_TS_AUTHKEY=tskey-auth-… hearth hub --tailscale
# or keep the key in a file only the hub's user can read
hearth hub --tailscale --tailscale-authkey-file /etc/hearth/ts.key
```

The node logs in once. Its state (the node key) goes in `<data-dir>/tailscale` (mode 0700). Later
starts need no auth key, so you can delete the key or let it expire. A new key is needed only if
you remove that directory, restore the hub from a [backup](backup.md) (backups leave the node state
out), remove the node from the tailnet, or its node key expires. Untagged nodes expire after 180
days by default: use a tagged key, or disable key expiry for the node in the admin console. A node
that needs a login again shows the error in the log and on the Tailscale card. The hub keeps running
on the LAN. Remove `<data-dir>/tailscale` and restart it with a new key.

The log line `tailscale: hub on the tailnet` gives the URL. So does **Settings → General →
Tailscale** in the UI, which shows the node's state, its MagicDNS name, its tailnet addresses, the
UI URL and the agent address. The card is read-only: flags on the hub set all of it.

| Flag | Env | Default | |
| --- | --- | --- | --- |
| `--tailscale` | `HEARTH_TAILSCALE` | off | Put the hub on the tailnet. |
| `--tailscale-hostname` | `HEARTH_TAILSCALE_HOSTNAME` | `hearth` | The node's name, the first part of its MagicDNS name. Lower-case letters, digits and `-`. |
| `--tailscale-authkey-file` | `HEARTH_TS_AUTHKEY_FILE` | | A file holding the auth key, mode 0600. |
| | `HEARTH_TS_AUTHKEY` | | The auth key itself. `--tailscale-authkey-file` wins if both are set. |

Flags win over the environment, as everywhere in Hearth. If `--tailscale` is on, the hub has never
logged in to the tailnet and there is no key, the hub refuses to start and says which variable or
flag to set. The hub never logs the auth key and never shows it in the UI: Tailscale errors are
shown with the key removed.

## What the hub serves on the tailnet

| Address | What |
| --- | --- |
| `https://<name>.<tailnet>.ts.net/` | Web UI and API, with a Let's Encrypt certificate from Tailscale (needs HTTPS certificates on in the tailnet) |
| `https://<name>.<tailnet>.ts.net:7443/` | Web UI, API and agent services, with a hub CA certificate that names the tailnet name and addresses |
| `http://<name>.<tailnet>.ts.net:7080/` | Plain HTTP: UI, `install.sh`, `/download/` and `/ca.crt` (WireGuard encrypts it on the tailnet) |

The ports follow `--listen` and `--http-listen`. Nothing listens on the tailnet for the
[cluster](cluster.md) port 7444 or for [MQTT](mqtt.md).

**Without tailnet HTTPS certificates** the hub logs a warning, and the UI's tailnet URL becomes
`https://<name>.<tailnet>.ts.net:7443/`. That address uses the hub CA: trust the CA once on the
phone as described in [HTTPS](https.md#3-trust-it-once-per-device). Turn on HTTPS certificates and
restart the hub to move to port 443. Tailscale gets the 443 certificate from Let's Encrypt. Its
name then appears in the public Certificate Transparency logs, which is true of every Tailscale
HTTPS certificate.

## Agents over the tailnet

Open **Add device** from the UI over the tailnet URL. The install command then names the tailnet:
`curl -fsSL http://<name>.<tailnet>.ts.net:7080/install.sh | sh -s -- …`. A device on the tailnet
runs it, enrolls at `<name>.<tailnet>.ts.net:7443` and keeps that address. The hub CA certificate
on the tailnet port names the MagicDNS name and the tailnet addresses, so the agent's mTLS check
passes as on the LAN. From the LAN, Add device gives the LAN address as before. The tailnet names
always come after the `--host` names, so they never become the preferred address.

The device needs Tailscale itself (`tailscaled` or the app), because the agent dials an ordinary
TCP address. Agents never run tsnet, so the agent's memory stays as it was.

## Clusters

Each master with `--tailscale` runs a tailnet node of its own. Give each one its own
`--tailscale-hostname` (`hearth-1`, `hearth-2`, …). If two use the same name, Tailscale renames
the second (`hearth-1`), and the UI shows the name it got. Storage-only members serve no UI, so
they never join the tailnet. An agent keeps the master address it enrolled with. Failover to
another master over the tailnet is not done yet, and the members' replication port (7444) does not
run over the tailnet. Members replicate over the LAN or whatever `--cluster-advertise` names
([#407](https://github.com/gvart/hearth/issues/407)).

## Privacy

The tailnet node sends Tailscale no logs: the hub turns off tsnet's log upload. Release builds also
leave out Tailscale's log uploader and features the hub doesn't use (SSH, Taildrop, exit nodes and
others) with Tailscale's `ts_omit_*` build tags. Like any Tailscale node, the hub talks to
Tailscale's coordination server and DERP relays to join the tailnet.

## Builds

The release archives and the container image include Tailscale. A `go build` without the
`tailscale` build tag leaves it out and keeps the binary about 15 MB smaller. In such a build,
`--tailscale` fails with `this build has no Tailscale; use the full release build`. `task build`
builds with it, like the release.
