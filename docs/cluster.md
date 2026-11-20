---
title: Cluster mode
description: Run three hubs with Raft so Hearth survives the loss of one.
---

A single hub is the default, and it needs none of this. A cluster of 3 hubs keeps Hearth running when
any one of them dies: enrollment, the UI, the CLI and agent connections move to the surviving hubs
within seconds, and no committed write is lost. The design is in
[design/ha-hub.md](design/ha-hub.md); this page is the operator's view.

Run 3 hubs (or 5, which survives 2 failures). Two hubs are no better than one: losing either loses the
majority, and the cluster stops accepting writes.

## How it works, in one paragraph

The hubs replicate their database with Raft. One hub is the **leader**; the others are **followers**.
Agents stream to the leader only. The UI, the API and the CLI work on every hub: reads come from the
hub's own copy, and writes made on a follower are forwarded to the leader. If the leader dies, the
others elect a new one in a few seconds, agents reconnect to it, and everything carries on.

## Ports and names

Each hub uses four ports. The defaults are below; all hubs must be reachable from each other on
the Raft and gossip ports, and from agents and browsers on the TLS port.

| Port | Flag              | Used by                                                       |
| ---- | ----------------- | ------------------------------------------------------------- |
| 7443 | `--listen`        | agents, the HTTPS UI and API, and hub-to-hub joins and writes |
| 7080 | `--http-listen`   | the plain HTTP UI and API, the installer, `/ca.crt`           |
| 7444 | `--raft-listen`   | Raft between hubs (mutual TLS with hub certificates)          |
| 7445 | `--gossip-listen` | membership gossip between hubs (TCP, mutual TLS, no UDP)      |

Give each hub its name with `--host`: the **first** `--host` is the name agents and the other hubs use
to reach that hub's TLS port, so it must resolve from your devices. `--advertise host:7444` is the
address the other hubs dial for Raft (default: this machine's hostname).

## Roles and membership gossip

Every host has a set of roles: `node` (the agent), `storage` (a store replica) and `master` (API,
UI, agent streams, automations). `hearth hub` is `master` and `storage`; `hearth agent` is `node`.
`--allow-roles` (env `HEARTH_ALLOW_ROLES`, default `storage,master` on a hub) lists the roles a host
may take; it is the host's capability ceiling, and a hub refuses to start if it does not allow both
of its roles.

Clustered hubs gossip their membership (hashicorp/memberlist) over TCP with mutual TLS on
`--gossip-listen` (default `:7445`, empty turns it off), with the same hub node certificates and
revocation checks as Raft: an enrolled device's certificate, a certificate of another CA or a
revoked hub certificate is refused. A member's gossip name is bound to its certificate: a hub adds a
member only after a TLS handshake it made itself to that member's address showed a hub certificate
for that name, so no hub can join, or be added, under another hub's name. What other hubs relay about
a member (its metadata, or that it is suspect or dead) is trusted as coming from a cluster hub, not
checked against the member itself. `--gossip-advertise` is the address the other hubs dial (default:
the `--advertise` host and the gossip port); every hub must gossip on the same port, because a hub
finds the others at its Raft peers' hosts on its own gossip port. Agents never gossip. For now
gossip only reports membership, next to Raft, which still replicates everything; gossip and
replication will share one port once Raft is replaced.

## Forming the cluster

On the first hub, with or without existing data (its devices, tokens and password are kept):

```sh
hearth hub --cluster --host hub-a.lan --advertise hub-a.lan:7444
```

`--cluster` is remembered in the data dir; later starts need no flag. Then create one join token per
new hub, on any member's host while its hub runs:

```sh
hearth cluster token create --hub-url https://hub-a.lan:7443
```

The token is single use and short lived. It hands the new hub the cluster's CA, private key included,
so treat it like the CA key. On each new hub, with an **empty** data dir:

```sh
HEARTH_JOIN_TOKEN=hearthj1.… hearth hub --join https://hub-a.lan:7443 \
  --host hub-b.lan --advertise hub-b.lan:7444
```

The new hub pins the CA by the fingerprint in the token, joins as a non-voter, receives a copy of the
database, and promotes itself to a voter once it runs. The new hub's Hearth must support the
cluster's database schema: the same version as the cluster or a newer one. An older one is refused.

## Checking on it

```sh
hearth cluster status          # on any member's host
hearth cluster status --json
```

It shows this hub's state, the leader, the Raft term and indexes, and every peer with its suffrage
and its database schema as `DATABASE/SUPPORTED`: the schema version its database is at and the
newest its Hearth supports (`?` and the reason when the hub does not answer). All peers should be
`Voter`, and every DATABASE column shows the same version. The `MEMBER` table lists the gossip members
with their address, roles, allowed roles, state and schema. A member is `alive`, `suspect` (gossip
holds it alive but this hub has heard nothing from it directly for about two probe rounds), `dead`
(failed) or `left` (stopped cleanly); `dead` and `left` members stay listed until this hub restarts. The `CONFIG` table compares each hub's
host flags (see [Host flag drift](#host-flag-drift)). In the hub logs, `leading the cluster` and `no longer leading the
cluster` mark leadership changes, and `caught up with the cluster` marks a hub that is ready after a
start.

## Configuration

`policy.yaml`, `notify.yaml`, the automation files and the runbook files are **documents of the
replicated store**, not files on each hub. Every hub holds the same documents and applies a change
within a few seconds, whichever hub it was written on, without a restart. They cannot differ between
hubs. Change them with `hearth config import` on any hub's host (see
[guardrails](guardrails.md#configuration-documents)), or with the web UI's automation editor and the
MCP `apply_automation` tool, which write automation documents.

The first hub to start on a database without documents imports its own files once (`config.import.first`
in the audit log); after that the files on disk are not read, and the hub says so once in its log. A hub
that joins later takes the cluster's documents. A cluster whose database is older than schema 28 keeps
reading each hub's files until `hearth cluster migrate` and a restart of each hub.

## Host flag drift

What still belongs to each host is its command line. `--allow-dangerous-automation` grants an
automation dangerous actions on that host only: a ceiling each host sets for itself. If hubs differ,
a failover changes which automations may act, so Hearth compares this flag across hubs and warns.

Each hub computes a SHA-256 digest of its `--allow-dangerous-automation` ids (in any order) and shares
it with the other hubs over the mutual-TLS hub channel. The web UI shows a warning under the top bar,
and `hearth cluster status` has a `CONFIG` table:

```text
CONFIG      STATE    HUBS
host_flags  differs  hub-a, hub-b | hub-c
```

| State     | Meaning                                                                  |
| --------- | ------------------------------------------------------------------------ |
| `in_sync` | Every hub reported the same flags.                                       |
| `differs` | At least two hubs reported different flags. Hubs are grouped by flags.   |
| `unknown` | No two hubs differ, but at least one hub could not be compared.          |

A hub is unknown, never counted as different, while it is down, still starting, or running a Hearth
too old to report host flags (an older hub's comparison of its files is ignored). A single hub has
nothing to compare and shows no warning. The warning needs a signed-in session, like the rest of the
API (`GET /api/v1/cluster/config-drift`). It names items and hubs only: digests are never shown, and
never logged.

**Resolving a warning.** Decide which grants you want, and start every hub with the same
`--allow-dangerous-automation` flags, restarting one hub at a time and waiting for `caught up with the
cluster` in its log before the next. To grant an automation everywhere instead, add it to
`dangerous_automations` in `policy.yaml` and import that.

## What happens when a hub fails

- **A follower dies.** Nothing visible happens. When it comes back it catches up from the leader.
- **The leader dies.** The remaining hubs elect a new leader within a few seconds. Agents notice their
  stream ended, try the other hubs they know, and are sent on to the new leader; expect them back
  within about 10 seconds. Devices stay online in the UI: a new leader counts every online device as
  seen when it took over and only marks one offline if it stays silent for the full offline timeout
  (30 s) after that.
- **Leadership moves while the leader is still alive** (for example after a network hiccup). The old
  leader ends every agent stream with a "not the leader" answer naming the new one, and the agents go
  there at once.
- **Two of three hubs are down.** There is no majority, so there is no leader. Reads still work on the
  surviving hub, with the data it had. Every write (logging in, creating a token, enrolling, an agent
  coming online) waits up to 5 seconds for a leader and then fails with HTTP 503
  `cluster_unavailable` (or a "cluster unavailable" CLI error); nothing is written. Agents keep
  retrying. Bring a second hub back and everything resumes. A write caught by a leader change (the
  leader steps down or hands over while applying it) also fails with 503 `cluster_unavailable`; it
  may or may not have been applied, and retrying it is safe.
- **A hub restarts.** Until it has caught up with the cluster, its API waits up to 5 seconds per
  request and then answers 503 `catching_up`; the UI shows the error and works again once the hub is
  ready, usually within a second or two.

CI holds the cluster to these: an end-to-end test (`task e2e:cluster`, in
[`test/e2e/cluster_test.go`](../test/e2e/cluster_test.go)) runs three hubs and an agent in Docker
Compose, kills the leader, takes the majority away and back, replaces a dead hub, and fails if any
step takes longer than its stated bound.

## Replacing a dead hub

A hub that is gone for good still counts towards the majority: a 3-hub cluster with one dead member
tolerates no further failure. Remove it, then join a new hub:

```sh
# on any surviving member's host
hearth cluster remove hub-c
hearth cluster token create --hub-url https://hub-a.lan:7443
# on the new hub, with an empty data dir (the old node ID may be reused)
HEARTH_JOIN_TOKEN=... hearth hub --join https://hub-a.lan:7443 --node-id hub-c --advertise hub-c.lan:7444
```

`hearth cluster remove` takes the hub out of the Raft configuration (right after it, two voters
remain and both are needed; once the new hub is a voter, the cluster tolerates one failure again)
and revokes every hub node certificate issued to it. A revoked certificate is refused on the Raft
port and by every hub-to-hub call (forwarded writes, promotion); Raft connections that were already
open are closed within 2 seconds. The node ID is free again: a new hub may join under it with a
fresh data dir and a new join token, and gets a new certificate.

It refuses to:

- **remove the leader.** Run `hearth cluster transfer-leadership [<node-id>]` first (without an ID,
  the most up-to-date voter takes over), then remove the old leader.
- **remove the last voter.**
- **break the majority.** A voter is only removed if the voters that still answer the leader are a
  majority of the voters that remain. With one hub dead, remove the dead one, not a live one.
- **remove an unknown ID.** Running a removal again after it was interrupted (the hub left the
  configuration but its certificates were not revoked yet) finishes it.
- **remove on a schema before 6.** Hub certificates are recorded from schema 6 on: after upgrading
  from v0.0.1-rc.3 or older, run `hearth cluster migrate` first. Until then no hub certificate is
  revoked, and each hub records its own once the cluster migrates.

Both commands are policy actions run by the local admin: `cluster.remove` (dangerous) and
`cluster.transfer_leadership` (safe), audited like any other.

Each hub records its node certificate in the cluster: the leader records the one it issues at join,
and every hub records its own once it has caught up after a start, which covers a certificate it
renewed itself (30 days before expiry) and certificates from before this was recorded. A hub that
died before it ever ran a version that records them has no recorded certificate to revoke; removing
it from the configuration still stops it from counting, and its old certificate is refused by
forwarded writes since it is no longer a member, but not on the Raft port.

## The UI on any hub

Open `https://<any hub>:7443` (or `http://<any hub>:7080`). Logins, token creation and everything else
work on every hub; on a follower, the write is forwarded to the leader. Sessions are replicated, but
cookies belong to a host name: switching from `hub-a.lan` to `hub-b.lan` means logging in again.
Give all hubs one shared DNS name (several A records) if you want one login to survive a failover.

Live updates (the device list changing as devices come and go) reach a UI on any hub. On a follower
the last-seen time can trail the leader's by up to 30 seconds, because the leader writes last-seen
times in batches; online and offline changes arrive as quickly as on the leader.

## Agents

Nothing to configure. An agent joins through any hub (a follower sends it to the leader), receives
the list of every hub's URL, keeps it in `hubs` in its data dir, and refreshes it on every connection.
When its hub goes away it tries the others in turn.

## Upgrading Hearth

A cluster upgrades one hub at a time, without downtime. A hub never migrates its database on its own:
a newer Hearth runs at the cluster's schema until you migrate the whole cluster, in step, through the
Raft log.

1. **Upgrade the followers, one at a time.** Install the new version and restart the hub; wait until
   `hearth cluster status` shows it as `Voter` again (and `caught up with the cluster` is in its log)
   before the next one. Each upgraded follower shows its new SUPPORTED version and the old DATABASE
   version.
2. **Transfer leadership** to an upgraded hub: `hearth cluster transfer-leadership` on any member's
   host.
3. **Upgrade the old leader** the same way.
4. **Migrate:**

   ```sh
   hearth cluster migrate --dry-run   # what it would do
   hearth cluster migrate             # to the newest schema every hub supports
   ```

   It prints every hub's schema and the target, and the leader then asks every hub again: if one runs
   a Hearth that does not support the target, or does not answer, it refuses and names it. On success
   every hub runs the migration at the same point of the log, and `hearth cluster status` shows the
   new DATABASE version everywhere. `--to N` picks another target.

A release without a new migration needs only steps 1 to 3 (`hearth cluster migrate` then says there is
nothing to migrate). Writes keep working throughout, apart from the usual election pause during the
leadership transfer. Do not migrate before every hub is upgraded: the leader refuses anyway.

Downgrades are not supported. Before the migration, a hub can go back to the previous version. After
it, an older Hearth refuses to start on the migrated database ("the database is at schema N, this
binary supports up to M"), and a hub joining the cluster needs the new version.

## Rotating the hub CA

Every hub holds the hub CA's private key, and so does every backup taken with the key. Rotating
replaces the CA with a new one, without downtime and without re-enrolling agents that are online.
Rotate when a hub's data dir, a copy of it, or a backup with the CA key may have leaked, when you
removed a hub whose data dir you could not wipe, or as routine hygiene.

Rotation is for clusters only: a standalone hub has no rotation command. To replace a standalone
hub's CA, delete `ca.crt` and `ca.key` and enroll every agent again.

**Before you start:**

- **Upgrade every hub and every agent first.** The cluster must be at the store schema that records
  rotations (run `hearth cluster migrate`). An agent older than this release ignores what the hub
  hands it during a rotation, so it is cut off at the finish and has to enroll again.
- **Remove a member you suspect first.** If a hub that is still a member may be compromised, remove it
  (`hearth cluster remove`), wipe it, and join it again with a new token before you rotate: a rotation
  hands the new key to every member.
- Every hub must be up.

**Steps**, on the leader's host (both commands refuse on a follower and name the leader):

1. **Start:**

   ```sh
   hearth cluster ca rotate --dry-run   # the plan: the hubs, and any certificate it cannot renew
   hearth cluster ca rotate
   ```

   The leader makes the new CA in its data dir. Every hub fetches the key and a node certificate of the
   new CA from the leader, over the cluster's mutual TLS, presenting exactly the node certificate the
   leader saw it use when the rotation started. Every hub now trusts both CAs and signs new
   certificates with the new one. The new key goes to the hubs' data dirs (`ca.next.key`, mode 0600)
   and never into the database, the Raft log or a snapshot. The rotation refuses, and lists them, while
   any certificate has no recorded fingerprint or someone presented another certificate with its serial:
   reconnect those agents, revoke them, or pass `--accept-unpinned` to cut them off at the finish.
   `--accept-unpinned` covers agents only: a hub whose node certificate has no recorded fingerprint is
   never given the new key, so the rotation refuses until you restart that hub (it records its
   certificate when it starts) or remove it.

2. **Let the agents renew.** Every agent that connects with the certificate the hub recorded for it
   gets a certificate of the new CA for its own key, and both CAs to trust. It reconnects with them at
   once. Watch it:

   ```sh
   hearth cluster ca status   # every hub's side, and the devices not renewed yet
   ```

   An agent adds a CA to trust only together with a certificate of it for its own key, and only if the
   CAs it is handed include the one that verified the hub it is connected to; otherwise it only drops
   CAs. Whoever held the old key during the rotation could still have posed as a hub to an agent and
   handed it a CA of their own this way: if you suspect that, check `ca.crt` in the data dir of the
   agents connected during the rotation, or enroll them again.
3. **Finish:**

   ```sh
   hearth cluster ca finish --dry-run
   hearth cluster ca finish
   ```

   It refuses while an agent or hub still holds only an old-CA certificate, and names them. `--force`
   finishes anyway and cuts them off. Otherwise every hub switches to serving the new CA, the sealed
   secrets in the database (kubeconfigs, Proxmox connections, runbook runs) are re-sealed with the new
   key, and every hub then drops the old CA and deletes its key. Connections that still use an old-CA
   certificate are closed. A finish that stopped part way, say because a hub restarted, resumes when
   you run it again: a hub that restarts after the switch serves the new CA from its start. The finish
   names the sealed secrets it checked, and is refused, and checks again, if any changed since. A
   sealed secret that opens with neither key (a corrupt row) stops the finish, which names it: remove that
   Kubernetes cluster or Proxmox server (in the UI, or `DELETE /api/v1/kube/clusters/{id}` or
   `DELETE /api/v1/proxmox/servers/{id}`), run the finish again, then add it back.

**Giving up.** Until the finish has begun to switch the hubs over, a rotation can be abandoned:

```sh
hearth cluster ca abort --dry-run   # lists the agents already renewed, which have to enroll again
hearth cluster ca abort
```

Every hub drops the new CA, its key and its node certificate of it, the certificates the new CA issued
are revoked, and hubs can join again. It is
also the way out when the leader that made the new CA is lost before another hub fetched its key:
nothing else holds that key, and a new leader cannot finish. Once the switch has begun, abort is
refused: finish the rotation instead.

**After the finish:**

- **An agent that was offline throughout is cut off** and has to enroll again, with a new token.
- **A hub the finish left behind** (with `--force`, or one that never got the new key) deletes its
  copy of the CA key, stops trusting the old CA and stops: it never serves the old CA again. Remove it
  (`hearth cluster remove`), wipe its data dir, and join it again with a new token. One cut off before the
  finish reached it keeps running, outside the cluster, with the old key: remove and wipe it all the
  same.
- **Browsers and phones** that trusted the old CA must trust the new one: fetch it again from
  `http://<hub>:<port>/ca.crt` (see [HTTPS for the web UI](https.md)).
- **Enroll and join tokens** made before the finish name the old CA and stop working: create new ones.
  No hub can join while a rotation is under way.
- **Backups taken before the finish still hold the old key** if they were taken with it. A backup taken
  during the rotation holds both CAs and restores as such; one taken after holds only the new CA. A
  cluster restored from a backup taken during the rotation is a rotation under way: finish it on the
  restored hub before the others join again (see [Restoring a cluster](backup.md#restoring-a-cluster)).
  A standalone hub restored from one drops the new CA when it starts, and logs that, as rotation
  needs a cluster: agents renewed or enrolled during the rotation have to enroll again.
  Destroy the old ones if the key's leak was the reason to rotate.

What a rotation does not undo: until the finish, whoever holds the old key can still pose as a hub to
browsers and agents and mint certificates the cluster accepts for agents (not for hubs: those must
match the certificate pinned when the rotation started). A leaked database also leaked the Kubernetes
and Proxmox credentials sealed in it: rotate those at their source, as re-sealing them with a new key
does not make the leaked copies useless.

The commands are policy actions run by the local admin, `cluster.ca.rotate`, `cluster.ca.finish` and
`cluster.ca.abort` (dangerous), and audited. A hub fetching the new key is the action `cluster.ca.fetch_key`, decided and
audited by the hub that serves it, refusals included (at most one entry a minute per caller for
refusals before the decision, counting those left out).

## CLI on a member's host

`hearth token create`, `hearth device revoke`, `hearth admin set-password`,
`hearth cluster token create`, `hearth cluster remove`, `hearth cluster transfer-leadership`,
`hearth cluster migrate` and `hearth cluster ca status` work on any member while its hub runs: they go
through the hub's local control socket and, on a follower, on to the leader. `hearth cluster ca rotate`,
`finish` and `abort` run on the leader's host only. With the hub stopped they refuse, since writing the local
database directly would diverge from the cluster.

## Policy and audit

Every action is decided and audited by the hub that received the request, exactly as on a single
hub. A forwarded write is replication only: the follower authenticates to the leader with its own
hub node certificate (never with a device or admin credential), and the leader applies the command
without a second decision. The audit entry is itself a write through the same path, so it lands in
the replicated log in order with the action.

An action's audit entry is written before the action runs, so a cluster that has lost its quorum
refuses every action, reads included, and says why. Agent heartbeats, the check of a signed-in
session and what the web UI reads from a hub's own database write no audit entry, so this refusal
does not affect them. Actions work again once a majority of hubs is back.

An action that was already running when the quorum went keeps the entry reporting how it ended.
The same goes for a held request that ends in a denial. The hub keeps that entry in the
`audit-spool` folder of its data dir and writes it once a majority is back, also after a restart.
The entry keeps the time it was made and lands only once. If a spooled entry cannot be read back,
the hub writes an `audit.entry_lost` entry in its place, so the gap shows in the audit log. The
entry lands only once on a cluster at schema 20 or later (see `hearth cluster migrate`). Below that,
a retried entry can show up twice.

## Limits

- **A removed member's data dir still holds the CA key.** Every member receives the hub CA's private
  key when it joins, and removal cannot take it back: whoever has that data dir can still mint
  certificates the cluster trusts until you [rotate the hub CA](#rotating-the-hub-ca). Wipe the data dir
  of every removed hub.
- **Schema migrations are manual and one way:** run `hearth cluster migrate` after upgrading every
  hub (see [Upgrading Hearth](#upgrading-hearth)); there is no automatic migration and no downgrade.
- All hubs share one CA, and every voter holds its key. Protect each hub's data dir accordingly.
- Clusters of 3 or 5 voters only; no read-only replicas.
- **Single-core hubs and old password hashes.** Admin password hashes set before
  [#94](https://github.com/gvart/hearth/issues/94) use four argon2 lanes, and checking one on a slow
  single-core hub (Pi Zero, Pi 1) can starve Raft long enough for that hub to lose leadership during
  a login. Run `hearth admin set-password` once after upgrading to re-hash with one lane.
