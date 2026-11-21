---
title: Security model
description: What protects the hub, the agents and your devices, and what you are trusting.
---

Hearth can restart services and run commands on your machines, so its rules are strict and few:
every action is decided by policy and audited, devices set their own ceiling, and every connection
between Hearth processes is mutually authenticated TLS.

## Rules

1. **Deny by default.** Every action from the UI, the CLI, an automation or another hub goes through
   one policy engine. An action it does not know is refused. See [Policy](concepts.md#policy).
2. **Everything is audited.** Each decision, allow or deny, is written to the audit log with the
   actor, the action and its target. Secrets (tokens, passwords, kubeconfigs, webhook URLs and
   headers, command arguments) never reach the audit log or the hub log.
3. **The device has the last word.** An agent runs only what its own `--allow-exec`,
   `--allow-restart`, `--allow-probe` and `--allow-shell` flags allow, streams only the logs its
   `--allow-logs` flag names, sweeps only the subnets its `--allow-scan` flag names and reports its
   neighbours and connections only with `--allow-net-edges`, lists and starts, stops and restarts its
   containers only with `--allow-docker`, and nothing by default. Nothing on the hub can raise that ceiling.
4. **Dangerous needs a name.** Actions of class `dangerous` (running a command, draining a node) are
   taken by an automation only when the hub is started with `--allow-dangerous-automation <id>` for
   that automation.
5. **Agents dial out.** Devices open no ports. Agents connect to the hub; the hub never connects to
   them.

## Identities and certificates

| Who            | Proves itself with                                                                 |
| -------------- | ---------------------------------------------------------------------------------- |
| Hub            | a server certificate from its own CA, issued at every start for its `--host` names |
| Agent          | a client certificate (one year) the hub CA signed at enrollment; the key never leaves the device |
| Another hub    | a hub node certificate from the same CA, issued when it joined the cluster          |
| Admin (web)    | the admin password (argon2id hash), then a session cookie that lasts 7 days         |
| Admin (CLI)    | access to the hub's data dir on the hub host                                       |

The hub CA is created on the first start in the hub's data dir (`ca.crt`, `ca.key`, mode 0600). Its
private key never leaves that directory, except to a new hub joining a cluster, over the pinned,
mutually authenticated join channel; to the members of a cluster during a hub CA rotation, over the
cluster's mutual TLS, and only to a member presenting exactly the node certificate pinned when the
rotation started (the key itself never enters the database, the Raft log or a snapshot); and inside
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
All three are dangerous policy actions for the local admin, audited. What it does and does not protect against:

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
- A leaked database also leaked the Kubernetes and Proxmox credentials and the notification channel
  credentials sealed in it, whatever the key: rotate them at their source.
- Enrollment and join tokens created before the finish stop working.
- Standalone hubs have no rotation: delete `ca.crt` and `ca.key` and enroll every agent again.

## Enrollment tokens

- **Single use** and **short lived**: 15 minutes by default (`hearth token create --ttl`), at most
  24 hours from the UI.
- **Stored hashed** on the hub: the database never holds a usable token.
- **Pinned**: a token carries the fingerprint of the hub CA. `hearth agent join` checks the hub's
  certificate against it before it sends the token, so a token is useless to an impostor hub.
- **Kept out of argv**: pass it as `HEARTH_TOKEN=<token>` or on stdin, never as an argument, which
  any local user can read with `ps`. The installer passes it to `hearth agent join` on stdin.

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
CPU priority so a login cannot starve the hub (or a cluster leader's heartbeats) of CPU; a login that
waits more than 10 seconds for its turn is answered `503 busy` with `Retry-After`. Behind a reverse
proxy every login comes from the proxy's address and shares one limit.

### Sensitive actions ask for the password again

A signed-in session is not enough for the most sensitive actions of the web UI: revoking a device,
creating or revoking an MCP token, saving the policy, changing a notification channel and downloading
a backup. Each asks for the admin password again, then goes through policy like any other action.

- An answer is good for **5 minutes**, for that session only, and is held in the hub's memory: a hub
  restart, a sign-out or a password change forgets it. Signing in counts as entering it.
- A missing or expired one is refused (`403 reauth_required`) and audited as a denial, before policy
  can hold the action for approval.
- A wrong one is refused (`403 reauth_failed`), audited as `admin.reauth` with the result `error: wrong password`, and limited like a
  login from the same address.

The admin password can be changed in **Settings** while signed in, given the current one; this is
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

## Integrations

- **Kubernetes**: kubeconfigs are sealed with AES-256-GCM (key derived from the hub CA key) before
  they reach the database. Credential plugins (`exec`, `auth-provider`) and `tokenFile` are refused,
  as they would run programs or read files on the hub. Each Kubernetes action is a policy decision;
  draining a node is dangerous. See [Kubernetes](kubernetes.md).
- **Proxmox VE**: API tokens only, sealed with AES-256-GCM under a key of their own. TLS is always
  verified, against a configured CA, a pinned certificate fingerprint or the system roots. Starting a
  guest is safe; stopping and rebooting one are dangerous. See [Proxmox VE](proxmox.md).
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
