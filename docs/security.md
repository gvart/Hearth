---
title: Security model
description: What protects the hub, the agents and your devices, and what you are trusting.
---

Hearth can restart services and run commands on your machines, so its rules are strict and few:
every action is decided by policy and audited, each device enforces its own ceiling, and every connection
between Hearth processes is mutually authenticated TLS. The [threat model](threat-model.md) maps these
rules to the trust boundaries they guard and lists the known residual risks.

## Rules

1. **Deny by default.** Every action from the UI, the CLI, an automation or another hub goes through
   one policy engine. An action it does not know is refused. See [Policy](concepts.md#policy).
2. **Everything is audited.** Each decision, allow or deny, is written to the audit log with the
   actor, the action and its target. Secrets (tokens, passwords, kubeconfigs, webhook URLs and
   headers, command arguments) never reach the audit log or the hub log.
3. **The device has the last word.** An agent runs only what its capability ceiling allows, and
   nothing by default: the programs, restarts, checks, logs, subnets, terminal, neighbours and
   containers and plugins it lets the hub use. The ceiling is its own `--allow-*` flags plus what an
   admin turns on in the device's **Capabilities** card (or `hearth device capabilities`). Turning on
   a terminal, programs, restarts, container control or a plugin is `dangerous` and asks for the
   admin password again;
   every change is audited, refusals too. The agent checks each ceiling the hub sends, saves it, and
   checks every request against the ceiling it holds, whatever the hub decided. An agent installed
   with `--local-ceiling` ignores the hub's settings: then nothing on the hub can raise its ceiling.
   See [Guardrails](guardrails.md#device-capability-ceiling).
4. **Dangerous needs a name.** Actions of class `dangerous` (running a command, draining a node) are
   taken by an automation only when the hub is started with `--allow-dangerous-automation <id>` for
   that automation.
5. **Agents dial out.** Devices open no ports. Agents connect to the hub; the hub never connects to
   them.

## Identities and certificates

| Who            | Proves itself with                                                                 |
| -------------- | ---------------------------------------------------------------------------------- |
| Hub            | a server certificate from its own CA, issued at every start for its `--host` names (default: its hostname, private LAN IPv4 addresses and loopback names) |
| Agent          | a client certificate (one year) the hub CA signed at enrollment; the key never leaves the device |
| Another hub    | a hub node certificate from the same CA, issued when it joined the cluster          |
| Admin (web)    | the admin password (argon2id hash), then a session cookie that lasts 7 days         |
| Admin (CLI)    | access to the hub's data dir on the hub host                                       |

**A hub-eligible enrollment token is as sensitive as the CA key.** An enrollment token made with
**This device may become a hub** (`"hub": true`, `hearth token create --hub`) lets the device that
uses it, if capable, get a join token granting master, and with it the CA key. So creating one takes
the admin password again in the web UI and is the policy action `cluster.token.create`, audited; the
master mints the device's join token as another audited `cluster.token.create`, by the enrollment
token, only while the master is not cut off from the cluster, bound to that device and valid 15
minutes, and only while fewer than 3 masters and 5 storage members exist or are on their way (the
join checks both again). The device writes the join token to `/var/lib/hearth/hub/join` (0600,
deleted after the join), and the CA key travels only over the join channel above. Untick the box for
a device you do not trust with the CA key; a plain enrollment token never leads to a hub.

The mint is audited and refused while the master is cut off, but your policy cannot deny it: the
decision for a `token` actor is fixed, so a hub-eligible token that is not yet used still mints its
device's join token after you change the policy, even to one that denies dangerous actions.
Revoking it is the way to stop it: revoke a hub-eligible token you no longer mean to use
([Revoking an enrollment token](#revoking-an-enrollment-token)), and give it a short TTL. The join
token is minted only when a device enrolls with the token, so a revoked token has minted none and
never will. The `device.enroll` audit entry says whether the join token was minted, with its roles,
or refused and why.

A hub-eligible device also counts as consent to a later promotion. A device that joined as storage
only (3 masters existed then) may be promoted to master, and receive the CA key, when a master is
removed and fewer than 3 are left ([Keeping 3 masters](cluster.md#keeping-3-masters)): you agreed to
it holding the key when you ticked the box. That promotion is the `cluster.promote` policy action by
the hub (actor `hub`), dangerous and audited with the reason `keep 3 masters`, and unlike the mint it
follows your policy: `confirm` holds it for approval, `deny` refuses it. The key still travels only
over the pinned `FetchCAKey` channel, granted only while that promotion runs. A hub that joined with a
join token from `hearth cluster token create` or **Add hub** is never promoted on its own.
`--keep-masters 0` turns automatic promotions off.

The hub CA is created on the first start in the hub's data dir (`ca.crt`, `ca.key`, mode 0600). Only
masters of a cluster hold it. Its private key never leaves a master's data dir, except to a new hub
joining a cluster as a master (with a join token that grants the master role, on a host that allows
it), over the pinned, mutually authenticated join channel; to a member being
promoted to master, and to the masters during a hub CA rotation, over the pinned, mutually
authenticated `FetchCAKey` channel, policy-checked and audited, and during a rotation only to a master
presenting exactly the node certificate pinned when the rotation started and proving it holds the
current key (the key itself never enters the store, the replication between hubs or a snapshot); and inside
a passphrase-encrypted [backup](backup.md) archive:
one that only an authenticated admin can create, through policy (`hub.backup`, from the CLI or the
web UI, where it also takes the admin password again) and with an audit entry,
or a scheduled one the hub uploads to a bucket, through policy (`hub.scheduled_backup`) and with an
audit entry, which holds the CA key only when the operator starts the hub with `--backup-include-ca`.
Whoever can read a hub's data dir can mint certificates the
whole installation trusts: protect it like a root password, and wipe the data dir of a hub you
remove from a cluster.

### Rotating the hub CA

A cluster can replace its CA (`hearth cluster ca rotate`, then `hearth cluster ca finish`, or
`hearth cluster ca abort` before the finish; see [Rotating the hub CA](cluster.md#rotating-the-hub-ca)).
All three are dangerous policy actions for the local admin, or for the web UI's **Cluster** page with
the admin password entered again, audited. What it does and does not protect against:

- Until the finish, both CAs are trusted, and whoever holds the old key can still pose as a hub to
  browsers and agents and mint agent certificates. Old-CA hub certificates are accepted only if they
  are exactly the ones pinned when the rotation started, so the old key cannot mint a new hub
  identity, and fetching the new key with a forged one is refused and audited. The same holds when a
  hub calls another (forwarded writes, fetching the new key, rotation status): the hub called must
  present its pinned node certificate or one of the new CA, not just any certificate of a trusted CA,
  so the old key cannot stand in for a member on the path. A hub whose node
  certificate has no recorded fingerprint is never pinned, `--accept-unpinned` or not. While the
  rotation is under way, a hub that cannot read its store to check a pin refuses old-CA hub
  certificates, and a hub asked whether it serves the new CA must show a certificate of it. After the finish,
  nothing of the old CA is trusted, including connections opened before it.
- An agent is renewed only for the exact certificate the hub recorded for it, on its own key. Agents
  that were offline, or run a Hearth older than the rotation, are cut off at the finish and enroll
  again.
- An agent adds a CA to trust only with a renewed certificate of it for its own key, at most two
  CAs, and only if they include the CA that verified the hub; otherwise it only drops CAs. Whoever
  held the old key could still, until the finish, pose as a hub and hand an agent a CA of their own
  with a certificate of it: if you suspect that, check `ca.crt` on the agents connected during the
  rotation, or enroll them again.
- A hub left behind by the finish deletes its CA key, stops trusting the old CA and stops; remove it
  and join it again.
- A hub that is still a member gets the new key. Remove and re-join a member you suspect before you
  rotate.
- Backups taken before the finish with the CA key still hold the old key. Destroy them if its leak is
  why you rotate.
- A leaked database also leaked the Kubernetes, Proxmox, ESPHome, OpenWrt, OPNsense and UniFi credentials and the notification channel
  credentials sealed in it, whatever the key: rotate them at their source.
- Enrollment and join tokens created before the finish stop working.
- A cluster of one can also replace its CA without a rotation: delete `ca.crt` and `ca.key` and enroll
  every agent again.

## Enrollment tokens

- **Single use** and **short lived**: 15 minutes by default (`hearth token create --ttl`), at most
  24 hours from the UI.
- **Stored hashed** on the hub: the database never holds a usable token.
- **Pinned**: a token carries the fingerprint of the hub CA. `hearth agent join` checks the hub's
  certificate against it before it sends the token, so a token is useless to an impostor hub.
- **Names its hub**: a token also carries the hub's agent URL, so the install and join commands need
  no hub address. The URL is not secret and not signed: a token edited to name another server fails
  the CA pin there, before the secret is sent. `--hub` gives another address to use.
- **Kept out of argv**: pass it as `HEARTH_TOKEN=<token>` or on stdin, never as an argument, which
  any local user can read with `ps`. The installer passes it to `hearth agent join` on stdin.
- **Revocable** until it is used: see below.

### Revoking an enrollment token

`hearth token list` on the hub host, or **Unused enrollment tokens** on the web UI's **Devices**
page, lists the tokens no device has used yet and that have not expired: an ID (the handle the
audit log names the token by, actor `token/<id>`), the device name and labels it gives, whether it
is hub-eligible, and when it expires. Never the token itself. `hearth token revoke <id>` or
**Revoke** spends the token: a device that tries it is refused (`enrollment token already used`).

Revoking is the policy action `token.revoke` (safe, by `admin` or `web`), audited with the token's
ID, refusals included. Revoking a hub-eligible token in the web UI asks for the admin password
again, as creating it did. A token already used, or expired, cannot be revoked: remove the device
that enrolled with it instead (`hearth device revoke`). In a cluster, a token belongs to the master
that created it, and only that master revokes it: elsewhere the revocation is refused and names
it.

The install command of a release hub fetches `install.sh` of the hub's own release tag from GitHub
over HTTPS; the installer then checks the binary's SHA-256 (and, with cosign, the release
signature). A hub you built yourself serves the installer over plain HTTP on port 7080 instead.

A device can be cut off with `hearth device revoke <device-id>` on the hub host, or with **Revoke
device** in its panel of the web UI: its certificates are revoked, the agent is disconnected within
10 seconds and exits instead of reconnecting.

## The web UI

The UI is served over plain HTTP on port 7080 and over HTTPS on 7443 with a certificate from the hub
CA. Trust the CA once per device to use HTTPS; see [HTTPS for the web UI](https.md). The HTTPS session
cookie is `Secure` and separate from the HTTP one. Over plain HTTP on a shared network, the password
and session cookie travel unencrypted: prefer HTTPS, or your own reverse proxy with TLS.

Logins are limited to 5 attempts in a row per client address, then one every 12 seconds (answered
`429` with `Retry-After`). The hub checks one password at a time, in a child process at the lowest
CPU priority so a login cannot starve the hub (or its cluster gossip) of CPU; a login that
waits more than 10 seconds for its turn is answered `503 busy` with `Retry-After`. Behind a reverse
proxy every login comes from the proxy's address and shares one limit.

### Sensitive actions ask for the password again

A signed-in session is not enough for the most sensitive actions of the web UI: revoking a device,
creating or revoking a hub-eligible enrollment token, creating or revoking an MCP token, saving the policy, changing a notification channel, downloading
a backup, creating a cluster join token (**Add hub**), upgrading a device's agent and starting, finishing or aborting a hub CA
rotation. Each asks for the admin password again, then goes through policy like any other action.

- An answer is good for **5 minutes**, for that session only, and is held in the hub's memory: a hub
  restart, a sign-out or a password change forgets it. Signing in counts as entering it.
- A missing or expired one is refused (`403 reauth_required`) and audited as a denial, before policy
  can hold the action for approval.
- A wrong one is refused (`403 reauth_failed`), audited as `admin.reauth` with the result `error: wrong password`, and limited like a
  login from the same address.

The admin password can be changed in **Settings → Access** while signed in, given the current one; this is
`admin.set_password` by `web` (dangerous) and signs out every session. A forgotten password is reset
on the hub host with `hearth admin set-password`, which stays CLI-only.

## The installer and releases

`install.sh` checks the SHA-256 of the archive it downloads against the release's `checksums.txt`.
When [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) v3+ is installed, it
also checks the keyless Sigstore signature of `checksums.txt`, which only the project's release
workflow can produce, and installs nothing if it does not verify. To verify by hand:

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/gvart/Hearth/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

The installer is served by the hub over plain HTTP (a fresh device does not trust the hub CA yet).
Someone who can tamper with your LAN traffic could swap it; the agent still pins the hub CA from the
token, but if that matters to you, download `install.sh` from the repository and check it before
running it.

### Remote agent upgrades

An admin upgrades a device's agent from its page or with `hearth device upgrade`: the policy action
`device.upgrade`, dangerous, only from a signed-in session with the admin password entered again
(signing in counts, for the CLI), and audited with the versions, refusals and failures too. Never an
automation or an MCP client.

- The hub sends the agent a release version and nothing else, over the agent's mutual-TLS stream.
  It cannot name a server, a file or a hash: **a hub, even a compromised one, can only make an agent
  install an official Hearth release, signed with the Hearth release key.**
- Each release's `checksums.txt` is signed with an Ed25519 key: `checksums.txt.sig` holds the base64
  of the signature over its exact bytes. The public key is compiled into the agent, and nothing at
  run time, neither a flag nor the environment, changes it. The agent downloads `checksums.txt` and
  `checksums.txt.sig` and checks the signature before it trusts any hash in it; a missing, malformed
  or wrong signature refuses the upgrade, with the reason in the upgrade's result and its audit entry.
  So whoever can change a release's assets on GitHub, without the signing key, cannot make agents
  install their code. goreleaser leaves the GitHub release a draft, in a job that never holds the
  key (it runs npm and other third-party code). A separate job, the only one with the secret
  `HEARTH_RELEASE_SIGNING_KEY` of the `release` environment (which needs the maintainer's approval),
  checks out the tag afresh, builds `internal/release/cmd/sign` (a program not in the `hearth`
  binary, which never prints the key and refuses one whose public half agents do not trust) with Go
  alone, downloads the draft, checks every archive against `checksums.txt`, signs it, uploads the
  `.sig` and only then publishes the release. That check catches an archive changed after
  goreleaser hashed it, not an archive and `checksums.txt` changed together in the goreleaser job.
  Only a build with the `e2etestkey` tag (the end-to-end tests' image) trusts another key; a release
  build has no variable an `-ldflags -X` could set. Releases up to v0.0.1-rc.11 are unsigned, and
  agents refuse them.
- The agent builds both URLs itself, from its compiled-in release base
  (`https://github.com/gvart/hearth/releases/download/<tag>/`) and its own platform: it reads the
  release's `checksums.txt`, then downloads its archive with a plain HTTPS client (not its device
  certificate), following redirects only while they stay HTTPS (GitHub sends assets on to its object
  storage), at most 128 MiB within 5 minutes. It refuses the archive if its SHA-256 differs from
  `checksums.txt`, reads at most 512 MiB out of it, runs the new `hearth version` and refuses it
  unless it names the version asked for. Only then does it rename the new binary over its own
  (synced to disk first), keeping the old one as `hearth.prev`, and exit with status 75 for systemd
  (`Restart=always`) or launchd (`KeepAlive`) to start the new one. Nothing changes on a failed check.
  The agent does not check the release's Sigstore bundle (that would take a large dependency): its
  trust is the Ed25519 signature above.
- The agent refuses a release older than the one it runs: no downgrades, so no way back to a release
  with a known flaw. Whatever it runs, a development build too, it never installs a release that
  cannot upgrade itself (v0.0.1-rc.10 or older).
- If the new binary does not reach a hub, it does not stay: until a hub welcomes it, a marker in the
  agent's data directory (`upgrade-pending`) counts its starts, and on the fourth start without a
  welcome, or once it has run 5 minutes without one, the agent puts `hearth.prev` back and exits for
  its service manager to start the old one. The old binary tells the hub in its next Hello
  (`rolled_back_from`, kept in `upgrade-rolled-back` in the data directory until a hub welcomes it):
  the hub records it in the audit log (`agent.upgrade.rolled_back`) and the device's page says the
  upgrade was rolled back, until the agent reports another version. The hub keeps a reported
  version only if it is a release tag of at most 64 bytes, audits it only when it differs from the
  one it holds, and puts it in the entry's detail. A binary that crashes before the agent even
  starts counting is not covered. By design, whoever can keep the upgraded agent from every hub for
  5 minutes (blocking the network, say) makes it go back to the previous release: it is still a
  release the agent ran, never an older one than that.
- An upgrade replaces the program that enforces the device's capability ceiling: it is above the
  ceiling, as re-running the installer is. That is why it is dangerous and takes the password. An
  agent started with `--local-ceiling` refuses every upgrade, as it refuses the hub's ceiling: upgrade
  it on the device with the installer. So does an agent with `HEARTH_NO_SELF_UPGRADE` set, or in a
  Kubernetes pod (upgrade its image).
- To replace its binary, the agent's systemd unit has `ReadWritePaths=/usr/local/bin` on top of
  `ProtectSystem=full`; the rest of its hardening stays.
- On a device that is also a hub, the hub runs the same `/usr/local/bin/hearth`: it keeps running the
  old version until its service restarts, and then runs the one the agent installed. Upgrade the
  hubs of a cluster first.
- `HEARTH_RELEASE_BASE_URL` in an agent's environment replaces its release base, as it does for
  `install.sh`. It is for the end-to-end tests only, not a supported setting; whoever sets an agent's
  environment owns its host already. It may be plain `http://` (the end-to-end tests' release
  server is), and it does not skip the signature, which is what makes a release trusted, whatever
  the transport: the end-to-end image is built with a test key in place of the release key.
- The audit entry of an upgrade records the version asked for, the version the agent ran, and the
  archive URL and SHA-256 the agent reports.

### Plugins on devices

An agent runs an [exec plugin](plugins.md#plugins-on-devices) only when its ceiling names it, with
the highest class of command the hub may send, and only the release the grant pins.

**Any plugin grant lets whoever can upload plugins run arbitrary code on the device as the agent's
user, whatever the class.** A class limits which commands the hub may send, not what the program does
once it runs. Allow only plugins you built or read, on devices where that user may do what the program
does.

- A release is a program and its manifest together, named by a digest: the SHA-256 of the program's
  SHA-256 and the manifest's. A grant the hub sets pins one release; the agent installs only that one
  and takes each command's class only from its manifest. Uploading a new program, or the same program
  with another manifest (other classes, arguments), makes a new release that no device runs until its
  grant is moved to it. The device keeps running the release it was allowed meanwhile, until its agent
  restarts: the hub offers only the latest release of each plugin, and a re-upload drops the program
  it replaces, so a restarted agent runs the plugin again only once its grant is moved to the new
  release (a known gap).
- Uploading a plugin's program is `plugin.binary.upload` (dangerous, the password again); its audit
  entry holds the program's SHA-256 and the release digest. Allowing a plugin on a device, raising its
  class, or moving it to another release ("approve" in the Capabilities card, `@latest` in the CLI) is
  `device.capabilities.raise` (dangerous, the password again). All are audited.
- An agent's own `--allow-plugin NAME[:CLASS]@DIGEST` pins a release on the device. Without `@DIGEST`
  the agent pins the first release it installs (trust on first use) by plugin name, keeps the pin in
  `<data-dir>/plugin-pins.json`, and refuses any other release while the flag stays, whatever its
  class; dropping the flag drops the pin. The hub is still trusted for that first release. If the pins
  file cannot be read, the agent installs and runs no plugin until it is fixed or removed. An agent
  with `--local-ceiling` takes plugins only from its own flags.
- The hub hands a device only the releases its grants allow: those the hub set for it (not on
  `--local-ceiling`) and those its own flags hold. The hub cannot verify an agent's own flags, which
  the agent reports itself, so any enrolled device can obtain any plugin's program and manifest. It
  cannot make the hub run that plugin anywhere else: commands go to a device only through policy.
- The agent downloads the program over mTLS with its own certificate, only for its own platform, at
  most 64 MB, streamed to disk, up to 512 MB of plugins in all. It checks the SHA-256 the release pins
  before it keeps the file (0700, in its data directory) and again before every start, and makes sure
  the file it starts is the one it checked. It runs the program with `exec`, no shell, a clean
  environment and its own process group, at most 4 commands at once; removing or replacing a release
  cancels its commands in flight.
- The agent refuses a command above the plugin's class in its own ceiling or one the manifest does
  not declare.
- A plugin's program, manifest and arguments are not secret: they are stored on every hub, and any
  enrolled device can fetch them. Keep settings and credentials in a file on the device.
- Device plugins do not run on Windows yet: the agent refuses them there.

## Integrations

- **Kubernetes**: kubeconfigs are sealed with AES-256-GCM (key derived from the hub CA key) before
  they reach the database. Credential plugins (`exec`, `auth-provider`) and `tokenFile` are refused,
  as they would run programs or read files on the hub. Each Kubernetes action is a policy decision;
  draining a node is dangerous. See [Kubernetes](kubernetes.md).
- **Proxmox VE**: API tokens only, sealed with AES-256-GCM under a key of their own. TLS is always
  verified, against a configured CA, a pinned certificate fingerprint or the system roots. Starting a
  guest is safe; stopping and rebooting one are dangerous. See [Proxmox VE](proxmox.md).
- **ESPHome**: API encryption keys (and legacy passwords) are sealed with AES-256-GCM under a key of
  their own, and never logged, served or audited. A device is read-only unless it was adopted with
  calls allowed; each switch or button call is a policy decision (`esphome.call`, safe) and audited.
  See [ESPHome](esphome.md).
- **OpenWrt**: the rpcd login is sealed with AES-256-GCM under a key of its own, and never logged,
  served or audited; so is the session ID. https is verified against the system roots or a pinned
  fingerprint; plain http sends the password in the clear. Hearth only reads, but for restarting
  dnsmasq (`openwrt.dnsmasq.restart`, dangerous), which asks for the admin password again. The
  router's rpcd ACL is the ceiling. See [OpenWrt](openwrt.md).
- **OPNsense**: the API key and secret are sealed with AES-256-GCM under a key of their own, and never
  logged, served or audited. Only https: the certificate is verified against the system roots or a
  pinned fingerprint. Hearth only reads, but for restarting Unbound (`opnsense.unbound.restart`,
  dangerous), which asks for the admin password again. The key's user privileges are the ceiling. See
  [OPNsense](opnsense.md).
- **UniFi**: the API key or local login is sealed with AES-256-GCM under a key of its own, and never
  logged, served or audited; so are the session cookie and the CSRF token. The controller is reached
  over https only, verified against the system roots or a pinned fingerprint. Hearth only reads, but
  for restarting an access point (`unifi.ap.restart`, dangerous), which asks for the admin password
  again. The account's UniFi role is the ceiling. See [UniFi](unifi.md).
- **Prometheus**: read only. Hearth never writes to Prometheus.
- **MCP clients** (AI assistants): each has its own bearer token, stored as a SHA-256 hash and
  checked on every request, so a revocation takes effect at once. The token's scope caps the class
  of action it may request; dangerous actions are held for approval by default. See [MCP](mcp.md).
- **Dashboards** (Homepage): a dashboard token is read-only. It is a bearer token for the
  dashboard summary alone (device counts and states, no addresses, facts or labels), stored as a
  SHA-256 hash, and created and revoked by a signed-in admin through policy. See
  [Homepage](homepage.md).
- **Notifications**: channel credentials (ntfy tokens, Telegram bot tokens) are in the `notify.yaml`
  document, sealed with AES-256-GCM (key derived from the hub CA key) before it enters the store, and
  re-sealed by a hub CA rotation. No API returns it; only `hearth config export` on a hub host writes it
  in clear. The web editor of channels is write-only: it shows whether each field is set, never its
  value, and an empty field keeps what is stored. Automations, the UI, run history and the audit log
  name a channel only.
- **Configuration documents**: policy, automations and runbooks are documents of the replicated store
  (see [guardrails](guardrails.md#configuration-documents)). Changing them is `config.import`
  (dangerous, audited), from the CLI or from the web editors of the policy, notification channels and
  runbooks (and deleting an automation), or `automation.apply` from the automation editor and MCP. Automation and runbook files
  are stored as written, not sealed: keep secrets such as webhook tokens out of them where you can.
- **Webhooks**: errors and the audit log name only a webhook URL's scheme and host, as URLs and
  headers often carry secrets.
