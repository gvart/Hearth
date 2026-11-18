---
title: Getting started
description: Run a hub and bring your first device into it in about five minutes.
---

By the end of this page you have a Hearth hub running and your first device (a Raspberry Pi, a NAS,
a laptop) showing up in its web UI. You need:

- **a machine for the hub**: Linux or macOS, amd64 or arm64. Your laptop is fine to try it out.
- **a device to add**: Linux (amd64, arm64, armv7) or macOS, on the same network, with `curl`.
- the hub's address as the device sees it: its LAN IP or a DNS name. Below it is `192.168.1.10`;
  use yours everywhere you see it. To find it: `ipconfig getifaddr en0` on macOS, `hostname -I` on
  Linux.

Hearth is pre-alpha: every release so far is a pre-release, `v0.0.1-rc.N`. The commands below use
`0.0.1-rc.5`; take the newest from the
[releases page](https://github.com/gvart/hearth/releases).

## 1. Download Hearth on the hub machine

Hub and agent are the same single binary. Pick the archive for the hub machine
(`darwin_arm64` for an Apple silicon Mac, `darwin_amd64`, `linux_amd64`, `linux_arm64` or
`linux_armv7`):

```sh
VERSION=0.0.1-rc.5
PLATFORM=darwin_arm64
curl -fsSLO "https://github.com/gvart/hearth/releases/download/v${VERSION}/hearth_${VERSION}_${PLATFORM}.tar.gz"
tar -xzf "hearth_${VERSION}_${PLATFORM}.tar.gz" hearth
./hearth version
```

If you would rather run the hub in Docker, skip this step and use the image
(`ghcr.io/gvart/hearth:v0.0.1-rc.5`) in the next one.

## 2. Start the hub

```sh
HEARTH_ADMIN_PASSWORD='choose-a-password' ./hearth hub --host 192.168.1.10
```

- `--host` is the name or IP your devices use to reach the hub. The hub's TLS certificate is issued
  for exactly these names, and devices refuse any other, so get it right. Repeat it to add more
  (`--host nas.lan --host 192.168.1.10`).
- `HEARTH_ADMIN_PASSWORD` sets the password of the web UI on the first start. Later starts ignore it;
  change the password with `hearth admin set-password`.
- The hub keeps its database and certificate authority in `~/.local/share/hearth/hub`
  (`/var/lib/hearth/hub` as root; `--data-dir` to choose).

It logs `hub listening` and keeps running in the foreground. Leave it running.

In Docker instead:

```sh
docker run -d --name hearth -p 7443:7443 -p 7080:7080 -v hearth:/var/lib/hearth \
  -e HEARTH_ADMIN_PASSWORD='choose-a-password' \
  ghcr.io/gvart/hearth:v0.0.1-rc.5 hub --host 192.168.1.10
```

**Firewall.** Devices must reach the hub on TCP ports 7443 and 7080. On macOS with the firewall on,
answer **Allow** when macOS asks whether `hearth` may accept incoming connections. On Linux, open
both ports if you run a firewall (`sudo ufw allow 7443,7080/tcp`).

## 3. Open the web UI and add a device

Open **`http://192.168.1.10:7080`**, using the same address you gave `--host`, not `localhost`:
the "Add device" dialog builds its install command from the address in your browser, and the device
cannot reach your `localhost`.

Sign in with the admin password, then click **Add device**. The dialog shows a command like:

```sh
curl -fsSL http://192.168.1.10:7080/install.sh | HEARTH_TOKEN=hearth1.… sh -s -- --hub https://192.168.1.10:7443
```

It holds a single-use enrollment token that expires after 15 minutes. Keep the dialog open: it tells
you when the device joins.

The UI also offers to switch to HTTPS. You don't need it to get started;
[HTTPS for the web UI](https.md) explains how when you want it.

## 4. Run the command on the device

On the device (over SSH, say), paste the command and **add `--version v0.0.1-rc.5` at the end**:

```sh
curl -fsSL http://192.168.1.10:7080/install.sh | HEARTH_TOKEN=hearth1.… sh -s -- --hub https://192.168.1.10:7443 --version v0.0.1-rc.5
```

Without `--version` the installer looks for the latest *stable* release, and while every release is
a pre-release it stops with `could not look up the latest release ... pass --version vX.Y.Z`.
Nothing is installed and the token is not used, so you can simply run it again with `--version`.
([#115](https://github.com/gvart/hearth/issues/115) will make this step unnecessary.)

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

### Without root

No `sudo` on the device? Run the agent as your own user instead. In the "Add device" dialog, open
**Hearth already installed?** and copy the **Join only** command. Then on the device:

```sh
VERSION=0.0.1-rc.5
PLATFORM=linux_arm64     # linux_amd64, linux_armv7, darwin_arm64, darwin_amd64
curl -fsSLO "https://github.com/gvart/hearth/releases/download/v${VERSION}/hearth_${VERSION}_${PLATFORM}.tar.gz"
tar -xzf "hearth_${VERSION}_${PLATFORM}.tar.gz" hearth
HEARTH_TOKEN=hearth1.… ./hearth agent join https://192.168.1.10:7443   # the "Join only" command, with ./
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

## 5. See it

The device is in the **Devices** list, online, with its OS, architecture and IP. Click it for its
facts. Stop the agent and it turns offline after 30 seconds; start it again and it is back at once.

## If it does not show up

| Symptom on the device                                   | Cause and fix                                                                                     |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `curl: (7) Failed to connect ... port 7080`             | The hub is not reachable: wrong address, hub not running, or a firewall (step 2).                |
| `could not look up the latest release`                  | Add `--version v0.0.1-rc.5` (step 4).                                                             |
| `enrollment token already used` or `expired`            | Tokens are single use and expire after 15 minutes. Click **Add device** again for a new one.      |
| `verify hub certificate: x509: certificate is not valid for ...` | The address in `--hub` is not one of the hub's `--host` names. Restart the hub with it added. |
| joined, but stays offline                               | The agent is not running (no systemd: start it yourself), or port 7443 is blocked.                |

On the hub, the log says `device enrolled` and then `agent connected` for each device.

## Next

- [Concepts](concepts.md): what the hub, agents, policy and the audit log do.
- [Automations](automations.md): restart a service when a check fails.
- [Prometheus](prometheus.md) and [Kubernetes](kubernetes.md): bring in what you already run.
- [Cluster mode](cluster.md): three hubs that survive the loss of one.
- [Security model](security.md): what protects your devices.
