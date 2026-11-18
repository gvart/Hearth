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
   `--allow-restart`, `--allow-probe` and `--allow-shell` flags allow, and streams only the logs its
   `--allow-logs` flag names, and nothing by default. Nothing on the hub can raise that ceiling.
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
mutually authenticated join channel, and inside a passphrase-encrypted [backup](backup.md) archive:
one that only an authenticated admin can create, through policy (`hub.backup`) and with an audit entry,
or a scheduled one the hub uploads to a bucket, through policy (`hub.scheduled_backup`) and with an
audit entry, which holds the CA key only when the operator starts the hub with `--backup-include-ca`.
Whoever can read a hub's data dir can mint certificates the
whole installation trusts: protect it like a root password, and wipe the data dir of a hub you
remove from a cluster.

## Enrollment tokens

- **Single use** and **short lived**: 15 minutes by default (`hearth token create --ttl`), at most
  24 hours from the UI.
- **Stored hashed** on the hub: the database never holds a usable token.
- **Pinned**: a token carries the fingerprint of the hub CA. `hearth agent join` checks the hub's
  certificate against it before it sends the token, so a token is useless to an impostor hub.
- **Kept out of argv**: pass it as `HEARTH_TOKEN=<token>` or on stdin, never as an argument, which
  any local user can read with `ps`. The installer passes it to `hearth agent join` on stdin.

A device can be cut off with `hearth device revoke <device-id>` on the hub host: its certificates are
revoked, the agent is disconnected within 10 seconds and exits instead of reconnecting.

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
- **Notifications**: channel credentials (ntfy tokens, Telegram bot tokens) stay in the channels
  file on the hub; automations, the UI, run history and the audit log name a channel only.
- **Webhooks**: errors and the audit log name only a webhook URL's scheme and host, as URLs and
  headers often carry secrets.
