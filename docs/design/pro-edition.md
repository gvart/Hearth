# Pro edition: multi-site, long retention, SSO

**Status:** proposal, not decided. Issue: [#82](https://github.com/gvart/hearth/issues/82).

## Problem

Hearth needs a way to pay for its development without taking anything away from the free core. The
roadmap's idea is a self-hosted license key for power users. This note proposes what a Pro edition
would hold, how it could be gated in code, and what the maintainer has to decide. Nothing here is legal
advice: the licensing points are questions to take to someone qualified.

## Principles

- **The core stays free and complete for one homelab.** Everything on `main` today stays in the free
  edition: devices, automations, runbooks, policy and audit, integrations, MCP, the cluster. Pro adds
  features for larger or longer-lived setups; it never moves an existing feature behind the key.
- **No phoning home** unless the owner turns it on. The key is checked offline.
- **Security never depends on the license.** Policy, audit, the ceiling and the CA rules work the same
  with or without a key. An expired key never locks anyone out of a hub or a device.
- **Local-first holds.** A Pro hub runs with no internet connection.

## What is in

### Multi-site

One view over several separate Hearth installations: a home lab, a parent's house, a rented server.

This is not the [cluster](../cluster.md). A cluster is one installation: one CA, every member reaches
every other on port 7444, members trust each other (crash faults, no Byzantine tolerance), and the
store is replicated. Sites are the opposite: different owners' networks, links that are slow or down
for days, and no reason for one site to hold another's CA key.

Proposed model:

- Each site stays a full installation (a cluster of one or more), with its own CA, policy and audit
  log. It keeps working on its own.
- A **site link** is a credential one site gives another, scoped like an MCP token today: the highest
  class of action it may request (`read` by default), held for approval on the target site as MCP
  requests are. The target site decides and audits every action, under its own policy.
- The connection is outbound from the site being managed, like agents today, so no site opens a port.
  Mutual TLS with a pin of each other's CA certificate, exchanged when the link is made.
- No replication between sites. The overview reads summaries (devices, states, alerts) on demand, and
  actions are forwarded one at a time.

Open: whether a site link is just an MCP-like token over the API (smallest change) or a new protocol.

### Long retention

What the free edition keeps today:

| Data | Kept |
| --- | --- |
| Built-in metrics | raw samples 24 h, rollups 7 days (`internal/metrics/store.go`) |
| Automation run history | the newest 100 runs per automation |
| Logs | not stored: streamed from the device on demand |
| Audit log | append-only, never deleted (a trigger refuses deletes) |

Pro could add: built-in metrics for months or a year, with coarser rollups; longer run history; an
audit export or forwarding to a file, syslog or S3 for retention outside the hub. The audit log is
already kept forever, so "long retention" for audit means export and search, not keeping more.

Sizing matters on a Pi: retention should be set in days and capped by disk, with the cost shown in the
UI. Note that users with Prometheus already get long metric history from it.

### SSO (OIDC)

Sign in to the web UI with an OpenID Connect provider (Authentik, Keycloak, Authelia, Google).

- Hearth has one admin account today. SSO without users and roles means "these OIDC subjects are the
  admin". Several users with roles is a larger change and a separate question.
- **Re-auth.** Sensitive actions ask for the admin password again. With SSO this needs an equivalent:
  an OIDC re-authentication with `prompt=login` and `max_age`, checking `auth_time`. It must stay as
  strong as the password prompt.
- **Break-glass.** `hearth admin set-password` on the hub host must keep working, so an IdP outage never
  locks the owner out. The password login could stay on, or be disabled with the CLI as the way back.
- **Cluster.** Sessions live on masters only today. The OIDC client secret would be a sealed global row,
  and every master would need its redirect URL registered with the IdP.
- Policy actions to turn SSO on, change it and map subjects, class `dangerous`, with the password
  again, audited.

Open: SSO is a common free feature in comparable tools (Beszel, Komodo and Homepage offer OIDC). Putting
it behind a key may cost goodwill. Consider making it free and keeping roles or multi-site paid.

## How it is gated

- **The key**: a signed document (customer, edition, features, expiry) signed with an Ed25519 key whose
  public half is compiled into the binary, as the release signing key is today (`internal/release/key.go`).
  Checked offline at start and daily. No network call.
- **Where it lives**: a global row in the store, so every master sees it. Setting it is a policy action
  (class to decide, at least `safe`, audited), from the CLI and the web UI.
- **What it gates**: only the Pro features above, each behind one check. Never policy, audit, ceilings,
  enrollment, upgrades or backups.
- **Expiry**: Pro features stop extending (no new sites, retention falls back to the free defaults
  without deleting data at once), with a warning in the UI well before. The hub keeps running.
- **Optional online check**: only if the owner turns it on, for example to refresh a key automatically.
  Off by default, and documented field by field, as [telemetry](../telemetry.md) is.

## Licensing questions (not legal advice)

- **License checks in AGPL code**: Hearth is AGPL-3.0 (with `pkg/` Apache-2.0). Can anyone remove a
  license check from the AGPL source and run or distribute the result, so that a key in AGPL code is
  only a request, not a lock? If so, is that acceptable, or should Pro code live elsewhere? To confirm
  with a lawyer.
- **Open core**: could Pro features live in a separate, non-AGPL module or repository, built into a
  Pro binary that the free binary does not include? What would that require of the AGPL core and of
  the boundary between them? To confirm with a lawyer.
- **Contributions**: the project uses a DCO, not a CLA. Can code contributed under the DCO and AGPL be
  used in a proprietary Pro module without each contributor's consent, or does Pro code have to be
  written by the maintainer or contributed under a CLA for that module? To confirm with a lawyer.
- **Trademark**: whether "Hearth Pro" should be protected so forks cannot sell under the name.

## Open questions for the maintainer

- **Pricing**: per installation, per site, per year; a homelab-friendly price; a free tier for
  non-commercial use.
- **Scope**: which of multi-site, long retention and SSO is Pro, and which is free.
- **Code model**: key-gated features in the AGPL repo, or an open-core module.
- **Users and roles**: part of SSO, part of Pro, or free.
- **Who sells and issues keys**, and how a lost key is reissued.
- **Relation to the hosted relay** ([#72](https://github.com/gvart/hearth/issues/72)) and paid plugins
  ([#75](https://github.com/gvart/hearth/issues/75)): one key for all, or separate.
