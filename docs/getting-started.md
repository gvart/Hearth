---
title: Getting started
description: Run a hub and bring your first device into it in about five minutes.
---

By the end of this page you have a Hearth hub running, your devices (a Raspberry Pi, a NAS, a mini
PC) showing up in its web UI, and, if you started on your laptop, two or more of those devices
running the hub in its place, so you can shut the laptop. You need:

- **a machine for the first hub**: Linux or macOS, amd64 or arm64. Your laptop is fine: the devices
  you add take over from it (step 7).
- **a device to add**: Linux (amd64, arm64, armv7) or macOS, on the same network, with `curl`.
- the hub's address as the device sees it: its LAN IP or a DNS name. Below it is `192.168.1.10`;
  use yours everywhere you see it. To find it: `ipconfig getifaddr en0` on macOS, `hostname -I` on
  Linux. The hub finds its LAN IP itself; you need it only to open the UI from another machine.

Hearth is pre-alpha: every release so far is a pre-release, `v0.0.1-rc.N`. The commands below use
`0.0.1-rc.10`; take the newest from the
[releases page](https://github.com/gvart/hearth/releases).

## 1. Download Hearth on the hub machine

Hub and agent are the same single binary. Pick the archive for the hub machine
(`darwin_arm64` for an Apple silicon Mac, `darwin_amd64`, `linux_amd64`, `linux_arm64` or
`linux_armv7`):

```sh
VERSION=0.0.1-rc.10
PLATFORM=darwin_arm64
curl -fsSLO "https://github.com/gvart/hearth/releases/download/v${VERSION}/hearth_${VERSION}_${PLATFORM}.tar.gz"
tar -xzf "hearth_${VERSION}_${PLATFORM}.tar.gz" hearth
./hearth version
```

If you would rather run the hub in Docker, skip this step and use the image
(`ghcr.io/gvart/hearth:v0.0.1-rc.10`) in the next one.

## 2. Start the hub

```sh
HEARTH_ADMIN_PASSWORD='choose-a-password' ./hearth hub
```

- The hub's TLS certificate names this machine's hostname, its private LAN IPv4 addresses
  (`192.168.x.x`, `10.x.x.x`, `172.16–31.x.x`) and `localhost`. Devices refuse any other name, and
  the install command names the LAN IP, so on one LAN nothing more is needed. A new certificate is
  issued at every start for the addresses of the moment, but devices keep the address they enrolled
  with: give the hub a fixed address (a DHCP reservation) or a DNS name with `--host`.
- `--host` replaces that list with the names and IPs you give, for a DNS name (`--host nas.lan`), a
  tailnet or VPN address, or an address behind a port forward. Repeat it to add more
  (`--host nas.lan --host 192.168.1.10`). The first one is the address install commands name.
- The hub also answers at **`hearth.local`** on the LAN: it announces that name over mDNS (next to
  the OS's own responder, Bonjour or avahi) and its certificate names it too. It is for your
  browser only; install commands never name it. `--no-lan-name` turns it off, for instance when two
  separate Hearth setups share a LAN (in a cluster, set it on every master or on none).
- `HEARTH_ADMIN_PASSWORD` sets the password of the web UI on the first start. Later starts ignore it;
  change the password with `hearth admin set-password`.
- The hub keeps its database and certificate authority in `~/.local/share/hearth/hub`
  (`/var/lib/hearth/hub` as root; `--data-dir` to choose).

It logs `hub listening` and keeps running in the foreground. Leave it running.

In Docker instead:

```sh
docker run -d --name hearth -p 7443:7443 -p 7080:7080 -v hearth:/var/lib/hearth \
  -e HEARTH_ADMIN_PASSWORD='choose-a-password' \
  ghcr.io/gvart/hearth:v0.0.1-rc.10 hub --host 192.168.1.10
```

In a container the hub sees only the container's own network, so pass `--host` with the host
machine's LAN IP there. Its `hearth.local` announcement does not leave Docker's default bridge
network either: use the IP, or run the container with `--network host` on Linux.

**Firewall.** Devices must reach the hub on TCP ports 7443 and 7080, and browsers looking up
`hearth.local` on UDP port 5353 (mDNS). On macOS with the firewall on, answer **Allow** when macOS
asks whether `hearth` may accept incoming connections. On Linux, open them if you run a firewall
(`sudo ufw allow 7443,7080/tcp` and `sudo ufw allow 5353/udp`).

## 3. Open the web UI and add a device

Open **`http://hearth.local:7080`** from any computer or phone on the LAN (or the hub's IP,
`http://192.168.1.10:7080`, where `.local` names do not resolve, such as some Android browsers and
devices on another VLAN; `http://localhost:7080` on the hub machine). The "Add
device" dialog builds its command for an address the device can reach: the one in your browser if
the certificate names it and it is not `localhost` or a loopback IP, else the hub's first certificate
name that is not loopback (its LAN IP, or your first `--host`). A bare hostname such as `nas` or
`mac.local` in your browser gives way to the LAN IP too, when the hub found one, and `hearth.local`
always does: agents never depend on it. The MCP, Homepage and panel-link snippets do the same when
your browser is at `hearth.local`, `localhost` or a bare hostname, so a container without mDNS can
reach the hub; any other address you opened, a reverse proxy's included, stays.

Sign in with the admin password, then click **Add device**. **This device may become a hub** is
ticked: the device may then join the hub's cluster as a hub too (step 7), so the token is as
sensitive as the hub's CA key, and the dialog asks for your admin password again before it shows
the command. Untick it for a device that should only run the agent. The dialog shows a command like:

```sh
curl -fsSL https://raw.githubusercontent.com/gvart/Hearth/v0.0.1-rc.10/deploy/install.sh | HEARTH_TOKEN=hearth2.… sh -s -- --version v0.0.1-rc.10
```

It holds a single-use enrollment token that expires after 15 minutes. The token also names the hub
(`https://192.168.1.10:7443`) and the fingerprint of its CA, so the command needs no hub address.
The device joins under its hostname unless you give it a name under **Name, expiry and labels**: 1
to 63 letters, digits, `.`, `-` or `_`, starting with a letter or digit. The command fetches the
installer of the hub's own release from GitHub over HTTPS and passes `--version`, so the device
gets the same release as the hub. (A hub you built yourself serves the installer instead:
`curl -fsSL http://192.168.1.10:7080/install.sh | HEARTH_TOKEN=hearth2.… sh`.) Keep the dialog open:
it tells you when the device joins.

The UI also offers to switch to HTTPS. You don't need it to get started;
[HTTPS for the web UI](https.md) explains how when you want it.

## 4. Run the command on the device

On the device (over SSH, say), paste the command as it is.

The installer downloads the agent for the device's platform from GitHub releases, checks its
SHA-256, installs it to `/usr/local/bin/hearth`, enrolls the device and starts the agent as a service
(systemd on Linux, launchd on macOS). It needs root: run as a normal user it uses `sudo` and asks
for your password. It ends with:

```text
hearth: done: this device should show up in the hub UI within seconds
```

The device appears in the UI as soon as its agent connects, typically within a second or two. If the
installer warned `systemd is not running here`, start the agent yourself with the command it
printed.

With **This device may become a hub** ticked, the installer also says whether the device becomes a
hub. Only a Linux device on amd64 or arm64 with at least 1.5 GiB of memory and 2 GiB of free disk
does; it says so (`This device becomes a hub (storage, master)`), installs a second service,
`hearth-hub`, and joins the cluster with it. Anything else (a Pi Zero, an armv7 board, a Mac) says
`This device stays an agent, not a hub` and why. To keep a capable device an agent anyway, add
`--agent-only` at the end of the command (after `sh -s --`).

### Without root

No `sudo` on the device? Run the agent as your own user instead. In the "Add device" dialog, open
**Hearth already installed?** and copy the **Join only** command. Then on the device:

```sh
VERSION=0.0.1-rc.10
PLATFORM=linux_arm64     # linux_amd64, linux_armv7, darwin_arm64, darwin_amd64
curl -fsSLO "https://github.com/gvart/hearth/releases/download/v${VERSION}/hearth_${VERSION}_${PLATFORM}.tar.gz"
tar -xzf "hearth_${VERSION}_${PLATFORM}.tar.gz" hearth
HEARTH_TOKEN=hearth2.… ./hearth agent join   # the "Join only" command, with ./
./hearth agent run
```

The agent keeps its identity in `~/.local/share/hearth/agent` and runs in the foreground; stop it
with Ctrl+C and start it again with `./hearth agent run` (in `tmux`, or with
`nohup ./hearth agent run > agent.log 2>&1 &`, to keep it running after you log out). Later, the
installer can turn it into a service: it keeps an existing identity only if it is in
`/var/lib/hearth/agent`, so re-enroll with a new token when you switch.

You can also create the token on the hub machine instead of in the UI:

```sh
./hearth token create --hub-url https://192.168.1.10:7443
```

`--hub-url` is the hub address the token names. Add `--name garage-pi` to have the device join
under that name instead of its hostname. A token no device has used yet shows under **Unused
enrollment tokens** on the **Devices** page and in `hearth token list`; revoke one you handed out
by mistake there, or with `hearth token revoke <id>`.

## 5. See it

The device is in the **Devices** list, online, with its OS, architecture and IP. Click it for its
facts. Stop the agent and it turns offline after 30 seconds; start it again and it is back at once.

The hub may do nothing on a new device yet. Its **Capabilities** card, on the device's page, turns
each thing on: logs, containers, a terminal, restarts, programs, checks, a scan from there. The
agent applies a change at once, with no restart. Turning on a terminal, programs, restarts or
container control asks for your password again. To keep that on the device alone, add
`--local-ceiling` at the end of the install command: then only the agent's own `--allow-*` flags
count (see [Guardrails](guardrails.md#device-capability-ceiling)).

## 6. Find the rest of your network

On the **Devices** page, click **Scan my network** (or run `hearth network scan` on the hub
machine). A few seconds later **On your network** lists the hosts the hub found on its LAN, each
with a [kind](discovery.md#kinds): router, printer, media, phone, computer, NAS, IoT or unknown.

- On a computer-like host, **Add device** opens the same dialog as in step 3, with the device name
  prefilled from the host's name: copy the one-liner and run it there.
- A printer, TV or router cannot run an agent: **Adopt** keeps it as a network device, seen by
  every scan but not controlled. See [Adopting a host](discovery.md#adopting-a-host).

In Docker, the hub sees your LAN only with host networking (see
[In a container](discovery.md#in-a-container)).

## 7. Let the laptop go

A hub on your laptop stops when the laptop sleeps. Add **at least two** hub-capable Linux devices
(step 6, with **This device may become a hub** ticked): each joins the cluster as a hub, and the
**Cluster** page lists them. The first three hubs are masters: each serves the UI, the API and the
agents and holds the CA key. Up to five hubs keep copies of the data (storage); a device added after
that stays an agent. A hub down for 24 hours is removed, and if it was a master another of these hubs
becomes one, so the cluster keeps 3 masters ([Keeping 3 masters](cluster.md#keeping-3-masters)). With two devices besides the laptop, either can die and nothing is lost.

A Mac, or a device you added without the box ticked, stays an agent. To make it a hub, open its page
and click **Make this device a hub** in its **Hub** card: after your admin password it shows a command
to run on the device, which keeps the agent and installs the hub service next to it. **Make
agent-only** on the same card takes a hub out again. See
[A device's page](cluster.md#a-devices-page-make-it-a-hub-or-agent-only).

Before you stop the laptop's hub, open its **Cluster** page, or run `hearth cluster status` on it:

```text
Safe to stop this hub:  yes
```

It says yes once every row the laptop holds has an up-to-date copy on another hub and another master
is live; a hub that just joined needs up to 30 seconds to catch up. See
[Is it safe to stop this hub?](cluster.md#is-it-safe-to-stop-this-hub). Then stop it (Ctrl+C). The
agents move to another master by themselves, and the UI is on every master: open
`http://hearth.local:7080` again, or a device's IP on port 7080, and sign in with the same password.

The laptop's data dir still holds the CA key: delete it (`~/.local/share/hearth/hub`), or keep the
laptop as a hub of the cluster by starting it again later.

## 8. Upgrade the agents

After you upgrade the hub, the **Devices** page marks each device whose agent is older with **Out of
date**. On the device's page, the **Agent version** card has **Upgrade agent**: after your admin
password, the agent downloads the hub's release from GitHub, checks its SHA-256 against the release's
`checksums.txt`, replaces `/usr/local/bin/hearth` (keeping the old one as `hearth.prev`) and restarts.
The device is back on the new version within seconds. From a terminal, on any machine that reaches
the hub's web address:

```sh
hearth device upgrade <device-id> --hub-url http://<hub>:7080   # --version v0.1.0 for another release
```

An agent from before remote upgrades (older than this release) cannot upgrade itself: its card shows
the installer's command instead. Run it on the device once; it keeps the device's identity, and
writes the service unit that lets the agent replace its binary. Every upgrade after that is remote.
An agent in a Kubernetes pod refuses: upgrade its image in the DaemonSet. The hub needs to reach
GitHub to read the release's checksums; a local mirror is not supported yet.

## If it does not show up

| Symptom on the device                                   | Cause and fix                                                                                     |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `curl: (7) Failed to connect ... port 7080`             | A hub you built yourself serves the installer: wrong address, hub not running, or a firewall (step 2). |
| `enrollment token already used` or `expired`            | Tokens are single use and expire after 15 minutes. Click **Add device** again for a new one.      |
| `verify hub certificate: x509: certificate is not valid for ...` | The hub address in the token (or in `--hub`) is not one of the hub's certificate names (its LAN IPs, or its `--host` list). Restart the hub with `--host` naming it. |
| `enroll with ...: dial tcp ...` or `no such host`       | The device cannot reach the hub at the address in the token (another subnet, a VPN). Re-run with `--hub https://<address>:7443` at the end (after `sh -s --`), an address in the hub's certificate, or restart the hub with `--host` naming one the device reaches. |
| joined, but stays offline                               | The agent is not running (no systemd: start it yourself), or port 7443 is blocked.                |

On the hub, the log says `device enrolled` and then `agent connected` for each device.

## Next

- [Concepts](concepts.md): what the hub, agents, policy and the audit log do.
- [Automations](automations.md): restart a service when a check fails.
- [Prometheus](prometheus.md) and [Kubernetes](kubernetes.md): bring in what you already run.
- [Cluster mode](cluster.md): several hubs, no leader, that keep working when one dies. Started on a
  laptop? Before you stop it, its Cluster page (or `hearth cluster status`) says whether it is
  [safe to stop](cluster.md#is-it-safe-to-stop-this-hub).
- [Security model](security.md): what protects your devices.
