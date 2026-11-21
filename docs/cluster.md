---
title: Cluster mode
description: Run several hubs as one leaderless cluster that keeps working when a hub dies or the network splits.
---

Every hub is a member of a cluster. A hub on its own is a cluster of one, and it needs none of this
page. Add hubs and Hearth keeps running when one of them dies: agents move to another hub within
seconds, every hub serves the UI, the API and the CLI, and a write survives the loss of any one
storage member.

The cluster has no leader. Each side of a network split keeps working on its own, and the two
converge when the split heals (AP, in CAP terms). Dangerous actions are the exception: a hub cut off
from every other member refuses them (see [Guarantees](#guarantees)).

## Roles

Every host has a set of roles. Any combination is valid:

| Role      | Runs                                                                      | Typical host             |
| --------- | ------------------------------------------------------------------------- | ------------------------ |
| `node`    | the agent: facts, heartbeat, exec                                         | anything: Pi, TV, phone  |
| `storage` | a replica of a share of the store (SQLite)                                | Pi 4/5, NAS, server      |
| `master`  | the API, the UI, MCP, agent streams, automations, runbooks, enrollment, the CA key | Pi 5, server     |

`hearth hub` is `master` and `storage`; `hearth agent` is `node`. Only `storage` and `master`
members gossip and replicate: agents never do, and the agent's idle budget is unchanged.

`--allow-roles` (env `HEARTH_ALLOW_ROLES`, default `storage,master` on a hub) lists the roles a host
may take. It is the host's capability ceiling: nothing in the cluster can give it a role outside that
list. Roles change at runtime (see [Promote, demote and remove](#promote-demote-and-remove)).

`hearth cluster status` says whether the cluster is **highly available**: it is not while it has
fewer than 2 storage members, or keeps fewer than 2 copies of each row.

## Ports and names

| Port | Flag               | Used by                                                                  |
| ---- | ------------------ | ------------------------------------------------------------------------ |
| 7443 | `--listen`         | agents, the HTTPS UI and API, and joins                                  |
| 7080 | `--http-listen`    | the plain HTTP UI and API, the installer, `/ca.crt`                      |
| 7444 | `--cluster-listen` | gossip and replication between members (TCP, mutual TLS with hub node certificates, no UDP) |

Every member must reach every other one on the cluster port; agents and browsers reach masters on the
TLS port. Give each hub its name with `--host`: the **first** `--host` is the name agents and the other
hubs use to reach that hub's TLS port, so it must resolve from your devices. `--cluster-advertise
host:port` is the address the other members dial for the cluster port (default: the first `--host`
name and the `--cluster-listen` port). Every member listens on the same cluster port: a hub finds the
one it joins at that hub's host on its own cluster port.

Membership is gossiped (hashicorp/memberlist, SWIM) over the cluster port, with the same hub node
certificates and revocation checks as every hub-to-hub call: an enrolled device's certificate, a
certificate of another CA or a revoked hub certificate is refused. A member's name is bound to its
certificate: a hub adds a member only after a TLS handshake it made itself to that member's address
showed a hub certificate for that name, so no hub can join, or be added, under another hub's name.
What other members relay about a member (its metadata, or that it is suspect or dead) is trusted as
coming from a cluster member. There is no shared gossip key.

## Forming and joining

A fresh `hearth hub` forms a cluster of one: a master and storage member with one copy of each row,
its own CA, and nothing else to set up. The headline demo is unchanged.

To add a hub, create a join token on a master's host while its hub runs:

```sh
hearth cluster token create --hub-url https://hub-a.lan:7443
```

Or click **Add hub** on the **Cluster** page of a master's UI (`POST /api/v1/cluster/tokens` with
`{"ttl": "15m", "allow_roles": ["storage", "master"]}`): it confirms that the token lets a new hub
receive the CA key, asks for the admin password again, then shows the token once, inside the command
to copy. The roles only set `--allow-roles` in that command; the token does not limit them. Both
ways are the policy action `cluster.token.create` (dangerous, by `admin` or `web`), audited with the
TTL and never the token, which is stored only as a hash and cannot be shown again.

It prints the token and the command for the new hub. The token is single use and short lived, and
belongs to the master that created it: join through that master. On the new hub, with an **empty**
data dir:

```sh
HEARTH_JOIN_TOKEN=hearthj1.… hearth hub --join https://hub-a.lan:7443 \
  --host hub-b.lan --cluster-advertise hub-b.lan:7444
```

The new hub pins the CA by the fingerprint in the token and gets a hub node certificate. It gets the
CA's private key only when its `--allow-roles` include `master`; a host without it holds the CA
certificate only and serves no API, UI or agent port. Treat a join token for a master like the CA key.

Then the hub finds the cluster by gossip. `--cluster-seeds` (env `HEARTH_CLUSTER_SEEDS`) adds
`host:port` cluster addresses of other members to find it by; the `--join` hub's is added on its own.
Until a joining or restarted member has found another member, it refuses critical writes (503)
rather than keep their only copy; if none is reached within 30 seconds it starts alone and says so in
its log. It imports its configuration files only once it has found the cluster and caught up, so it
takes the cluster's documents instead of its own.

The new hub's Hearth must support the schema the cluster has written: the same version as the
cluster or a newer one (see [Upgrading Hearth](#upgrading-hearth)). An older one is refused.

**Away too long.** Deleted rows are forgotten after 7 days. A member that has not reached the cluster
for longer refuses to start with its old data, so it cannot bring deleted rows back: clear its data
dir and join it again.

## How data is kept

- **Placement.** A consistent-hash ring over the `storage` members places each row on `--replicas`
  members (env `HEARTH_REPLICAS`, default min(2, storage members), never below 1). Rows that belong
  together stay together: a device's certificates with the device, runs with their automation or
  runbook, an action's audit entries with each other. Small global tables (the admin password, hub
  certificates, configuration documents, Kubernetes and Proxmox connections, network hosts, telemetry
  settings) are on every storage member.
- **Writes.** Audit entries, certificates, revocations, tokens, sessions, approvals and configuration
  documents are **critical**: they need W = min(2, N) replicas and fail at once with 503
  `cluster_unavailable` when fewer are reachable. Other writes (presence, facts, scans, run history)
  need one replica and reach the others in the background. A replica that is down is replaced by the
  next live member, and gets the write later from a hint (kept in `hints.db`, bounded).
- **Reads.** A read by key goes to the nearest live replica (R = 1). When that replica has no copy of
  the row at all (it missed the write while it was down), a sign-in session, certificate, approval or
  approval link, device, device route or panel is asked of every live replica, and the newest copy
  wins, a deletion included. A list asks every storage member and merges the answers. A stale copy a read sees is repaired. Members compare digests of the rows
  they share and copy what differs (anti-entropy), so replicas converge after an outage or a split.
- **Conflicts.** Every row carries a hybrid logical clock (HLC) stamp and the member that wrote it.
  Two writes to the same row merge by **last writer wins** on that stamp. Some rows do not merge this
  way: the audit log is append-only (entries are only ever added); a revocation, once any replica has
  it, is never cleared by a later write (deny wins); and a token, an approval or an approval link is
  decided only by the master that owns it (below).
- **Clocks.** A member refuses a stamp more than 60 seconds ahead of its own clock, so a host with a
  wrong clock cannot win every conflict. Keep the hosts' clocks in sync (NTP).

## Masters

- **Every master serves agents.** An agent streams to any master. It gets the list of masters when it
  enrolls and on every connect, keeps it in `hubs` in its data dir, and moves to another master, with
  the usual backoff, when its master goes away. The master holding a device's stream records it (a
  `device → master` route); an exec, probe, Docker call, scan, log stream or terminal for that device
  on another master is forwarded to it over the members' mutual TLS. For an exec, probe, Docker call
  or scan, the decision and the audit entry stay on the master that got the request; a log stream or
  terminal is proxied whole and decided on the holder. If the holder cannot be reached, the call fails
  with "agent not connected" until the agent has moved; one lost after it was sent has an unknown
  outcome.
- **Presence.** The master holding a device's stream marks it online and offline. A device with no
  live stream is marked offline by the master that owns it on a hash ring over the live masters, once
  that master has owned it for 30 seconds.
- **Automations and loops.** An automation's schedule, check and metric triggers run on the master that
  owns it on the same ring, as do runbook runs and the expiry of pending approvals; when a master
  dies, its share moves to the others. Device and network-discovery triggers fire on the master where
  the event happens (the one holding the device's stream, or running the scan), and a manual run on
  the master it is asked of: each event happens on one master, so an automation fires once. Rows
  copied from other members raise no automation events. Network discovery, the DHCP/Pi-hole import,
  scheduled backups and telemetry run on one master each; Beszel and Talos reads on every master.
  During a split both sides may run one: accepted.
- **Tokens and approvals have an owner.** An enrollment token, a join token, an approval and an
  approval link belong to the master that created it, and only that master consumes or decides it, so
  "single use" holds without a quorum; another master refuses with an error naming the owner. An
  enrollment token carries its master's URL, and `hearth agent join` enrolls there. If the owner is
  down, its tokens wait for it: create a new one on another master. Expiry by the sweep is the only
  decision another master makes.
- **CA key on masters only.** Every master holds the hub CA's key in its data dir (0600). A storage-only
  member never has it.

## Guarantees

- **No lost critical write while one storage member is down.** A critical write is acknowledged only
  once two replicas hold it (when N ≥ 2).
- **Writes on both sides of a split.** Each side keeps writing to the replicas it reaches; the sides
  converge by last writer wins when the split heals. Critical writes still need two replicas on the
  writer's side.
- **Cut off, fail closed.** A master that has reached no other member for 60 seconds refuses
  `dangerous` actions and new enrollments and joins (each denial audited with the reason); reads and
  `safe` actions keep working, and the block lifts as soon as a peer answers. A cluster of one is never
  cut off.
- **Revocations travel fast.** A revocation (device or hub certificates, MCP or dashboard tokens,
  panel links) is a critical write and is also announced on the gossip at once; members that hold the
  row fetch it from the writer, without waiting for anti-entropy. A revoked credential can be used on
  a cut-off master for at most the 60 seconds before it fails closed, and then only for `safe` actions.
- **Every action is decided and audited.** An action is decided by the master that received it, and its
  audit entry is a critical write made before the action runs. A cluster that cannot place that entry
  refuses the action and says why.

## Promote, demote and remove

A member's roles change at runtime, within its own `--allow-roles`. Each change is a `dangerous`
policy action (`cluster.promote`, `cluster.demote`, `cluster.remove`), decided and audited with its
outcome on the master asked, and refused by a master that is cut off. Ask a master: on the **Cluster**
page of its UI (members, roles, allowed roles, state and progress), its API
(`POST /api/v1/cluster/members/{id}/promote|demote` with `{"role": "storage"}` or `"master"`,
`DELETE /api/v1/cluster/members/{id}`), or its host's CLI:

```sh
hearth cluster promote hub-d storage
hearth cluster demote hub-b master
hearth cluster remove hub-c          # a member gone for good
```

- **The member decides its ceiling.** A role outside the member's `--allow-roles` is refused, by the
  master and by the member itself. The roles are recorded in the member's data dir (`cluster/roles`),
  so they survive a restart, and are announced on the gossip. An agent host cannot take a role: run
  `hearth hub --join ...` on it to make it a member.
- **Promote to storage.** The member drops the rows it kept from before, joins the ring and copies its
  share from the others. It shows `syncing`, and serves no reads, until it holds them all.
- **Promote to master.** The member fetches the CA key from the master promoting it, over that master's
  mutually authenticated, pinned TLS channel (`FetchCAKey`, allowed only during that promotion, audited
  as `cluster.ca.fetch_key`), then serves the API, the UI and agents.
- **Demote from storage.** The member hands its rows to the members that will own them and keeps the
  role (`draining`, with its progress) until each row has its copies there; a future owner that is down
  holds it up until it is back. The last storage member is not demoted.
- **Demote from master.** The member spends its unused enrollment and join tokens, expires its pending
  approvals (`expired: master demoted`), deletes its CA key and stops serving the API, the UI and
  agents; its agents move to the other masters and its share of the masters' work moves with the ring.
  The last master is not demoted, and every member keeps at least one of the two roles.
- **Remove.** `cluster remove` revokes the member's hub certificates (announced on the gossip at once),
  every member drops it from its listing, and the others re-replicate the rows it held. A hub does not
  remove itself, nor the last master or storage member. To come back, it joins again with a new token
  and an empty data dir.

## Checking on it

```sh
hearth cluster status          # on any member's host
hearth cluster status --json
```

It shows this member, the number of storage members, N, and whether the cluster is highly available,
then the `MEMBER` table: every member with its address, roles, allowed roles, state and the newest
schema its Hearth supports. A member is `alive`, `suspect` (gossip holds it alive but this hub has
heard nothing from it directly for about two probe rounds), `dead` (failed) or `left` (stopped
cleanly), with `syncing` or `draining` and its progress while its roles change. `dead` and `left`
members stay listed until this hub restarts. A line under the table names the members whose host flags
differ (see [Host flag drift](#host-flag-drift)). In the hub log, `caught up with the cluster` marks
a member that is ready after a start.

## Configuration

`policy.yaml`, `notify.yaml`, the automation files and the runbook files are **documents of the
replicated store**, not files on each hub. Every hub holds the same documents and applies a change
within a few seconds, whichever master it was written on, without a restart. Change them with
`hearth config import` on a master's host (see [guardrails](guardrails.md#configuration-documents)),
or with the web UI's editors and the MCP `apply_automation` tool.

The first hub to start on a database without documents imports its own files once (`config.import.first`
in the audit log); after that the files on disk are not read, and the hub says so once in its log. A hub
that joins later takes the cluster's documents.

## Host flag drift

What still belongs to each host is its command line. `--allow-dangerous-automation` grants an
automation dangerous actions on that host only: a ceiling each host sets for itself. If masters differ,
which master owns an automation decides whether it may act, so members gossip a SHA-256 digest of
their `--allow-dangerous-automation` ids (in any order) and `hearth cluster status` names the groups
that differ:

```text
Host flags differ (--allow-dangerous-automation):  hub-a, hub-b | hub-c
```

Digests are never shown or logged. To resolve it, start every hub with the same
`--allow-dangerous-automation` flags, one hub at a time. To grant an automation everywhere instead, add
it to `dangerous_automations` in `policy.yaml` and import that.

## What happens when a hub fails

- **A master dies.** Its agents notice their stream ended and move to another master; expect them back
  within about 10 seconds. Its share of the automations, runbooks and sweeps moves to the other
  masters. Devices whose agents are back stay online.
- **A storage member dies.** Reads and writes go to the other replicas, and the dead member's writes
  wait as hints. With N = 2 and two or more other storage members live, critical writes keep working.
- **Too few storage members are left** for a critical write (fewer than 2 when N ≥ 2): logging in,
  creating a token or enrolling fails with HTTP 503 `cluster_unavailable` (or a "cluster unavailable"
  CLI error); nothing is written. Reads and non-critical writes keep working. Bring a member back and
  everything resumes.
- **The network splits.** Both sides keep working with the replicas they reach, and converge when the
  split heals. A master that reaches no other member fails closed for dangerous actions after 60
  seconds.
- **A hub restarts.** Until it has caught up with the cluster, its API waits up to 5 seconds per request
  and then answers 503 `catching_up`; the UI shows the error and works again once the hub is ready.

CI holds the cluster to these: an end-to-end test (`task e2e:cluster`) runs hubs and an agent in
Docker Compose, kills a master and a storage member, splits the cluster and heals it, and fails if any
step takes longer than its stated bound.

## Replacing a dead hub

Remove it, then join a new one:

```sh
# on a surviving master's host
hearth cluster remove hub-c
hearth cluster token create --hub-url https://hub-a.lan:7443
# on the new hub, with an empty data dir (the old node ID may be reused)
HEARTH_JOIN_TOKEN=... hearth hub --join https://hub-a.lan:7443 --node-id hub-c --cluster-advertise hub-c.lan:7444
```

`hearth cluster remove` revokes every hub node certificate issued to the member, and the revocation is
refused on the cluster port and by every hub-to-hub call from then on. The node ID is free again: a new
hub may join under it with a fresh data dir and a new join token, and gets a new certificate. A storage
member that is down for good holds up a demotion whose rows it would own: remove it first.

## The UI on any master

Open `https://<any master>:7443` (or `http://<any master>:7080`). Logins, token creation and everything
else work on every master. Sessions are replicated, but cookies belong to a host name: switching from
`hub-a.lan` to `hub-b.lan` means logging in again. Give all masters one shared DNS name (several A
records) if you want one login to survive a failover.

Live updates (the device list changing as devices come and go) reach a UI on every master, whichever
master the device's agent streams to. For a device on another master they arrive as its rows are
replicated, usually within a second or two.

## Upgrading Hearth

Upgrade one hub at a time, in any order, without downtime: install the new version, restart the hub
and wait for `caught up with the cluster` in its log before the next.

There is no migration command. A member migrates its own database when it starts, and gossips the
newest schema its binary supports. A table or column a migration added is written only once every live
member supports it, so during a rolling upgrade the cluster writes at the oldest live member's schema.
The newest schema the cluster has written is kept in each member's `cluster/schema-written` and never
goes back: a member, or a joining hub, whose Hearth supports less is refused. Upgrade before you bring
an old member back. Downgrades are not supported.

## Node certificates

A hub node certificate is valid for a year. A master renews its own with the CA key, at start; a member
holding no CA key asks a master for a new one while it runs, once its certificate expires within 30
days (the action `cluster.node_cert.renew`, safe, decided and audited by the master). Each member
records its node certificate in the cluster, so `cluster remove` can revoke it.

## Backups

A backup (`hearth backup`, a scheduled one, or **Settings → Backup** in the UI) taken on a master copies
the whole cluster store from the live members, every shard included, and is refused while some shard
has no live replica. A hub restored from a backup forms a new cluster of one, in a new cluster epoch:
members of the old cluster are refused until they join it again. See
[Restoring a cluster](backup.md#restoring-a-cluster).

## Rotating the hub CA

Every master holds the hub CA's private key, and so does every backup taken with the key. Rotating
replaces the CA with a new one, without downtime and without re-enrolling agents that are online.
Rotate when a master's data dir, a copy of it, or a backup with the CA key may have leaked, when you
removed a master whose data dir you could not wipe, or as routine hygiene.

**Before you start:**

- **Upgrade every hub and every agent first.** An agent older than this release ignores what the hub
  hands it during a rotation, so it is cut off at the finish and has to enroll again.
- **Remove a member you suspect first.** If a master that is still a member may be compromised, remove
  it (`hearth cluster remove`), wipe it, and join it again with a new token before you rotate: a
  rotation hands the new key to every master.
- **Every member must be up.** `rotate` needs every member alive.

Run the commands on a master's host. The running hub decides them with its policy engine, so a master
that is cut off refuses them.

The **Cluster** page of a master's UI does the same in its **Hub CA** section: the stage, the owner,
each member's progress (and who a finish still waits for), the agents not renewed yet, and **Start
rotation**, **Finish rotation** and **Abort rotation** (`GET /api/v1/cluster/ca`,
`POST /api/v1/cluster/ca/rotate|finish|abort`). Each step says what it does, asks for the admin
password again, and runs on the master that received it under the same rules as the CLI: the owner
drives it, another master refuses naming the owner while the owner is alive, and an isolated master
refuses. A step refused there is audited as a denial with its reason. `--accept-unpinned` and
`--force` stay CLI-only. Use the plain HTTP UI (port 7080) for the finish, or fetch the new CA from
`/ca.crt` after it: a browser that trusted only the old CA stops trusting the hub's HTTPS.

1. **Start:**

   ```sh
   hearth cluster ca rotate --dry-run   # the plan: the members, and any certificate it cannot renew
   hearth cluster ca rotate
   ```

   The master makes the new CA in its data dir and owns the rotation. Each member's node certificate is
   pinned as it presents it on the gossip. Each member then fetches a node certificate of the new CA
   from a master holding the new key, the owner first, over the masters' mutual TLS, presenting exactly
   the pinned certificate. A master also fetches the new key (`FetchCAKey`, proving it holds the current
   CA key); a storage-only member never gets it, and keeps no `ca.next.key`. Every member now trusts
   both CAs, and masters sign new certificates with the new one. The new key goes to the masters' data
   dirs (`ca.next.key`, mode 0600) and never into the store, the replication stream or a snapshot.
   Until the rotation ends no hub joins, and no member is promoted to master or demoted from it.

   The rotation refuses, and lists them, while any agent certificate has no recorded fingerprint or
   someone presented another certificate with its serial: reconnect those agents, revoke them, or pass
   `--accept-unpinned` to cut them off at the finish.

2. **Let the agents renew.** Every agent that connects with the certificate the hub recorded for it
   gets a certificate of the new CA for its own key, and both CAs to trust. It reconnects with them at
   once. Watch it:

   ```sh
   hearth cluster ca status   # every member's side, and the devices not renewed yet
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

   It runs on the master that owns the rotation while it is alive; another master refuses, naming it.
   It refuses while an agent still holds only an old-CA certificate, and names them; `--force` finishes
   anyway and cuts them off. It waits until every member holds the new CA, then cuts over (each master
   writes `cluster/ca-cutover` first, so a restart serves the new CA again at once), re-seals the sealed
   secrets in the store (kubeconfigs, Proxmox connections, runbook runs) with the new key, and every
   member drops the old CA and every master deletes its key. Connections that still use an old-CA
   certificate are closed. A member that is down stops the finish at once with its name: bring it back
   and run the finish again, or remove it. Every stage is resumable: run the command again. A sealed
   secret that opens with neither key (a corrupt row) stops the finish, which names it: remove that
   Kubernetes cluster or Proxmox server (in the UI, or `DELETE /api/v1/kube/clusters/{id}` or
   `DELETE /api/v1/proxmox/servers/{id}`), run the finish again, then add it back.

**Giving up.** Until the finish has begun to cut over, a rotation can be abandoned:

```sh
hearth cluster ca abort --dry-run   # lists the agents already renewed, which have to enroll again
hearth cluster ca abort
```

Every member drops the new CA, its key and its node certificate of it, the certificates the new CA
issued are revoked, and hubs can join again. Once the cut-over has begun, abort is refused: finish the
rotation instead.

**The owner died.** Once the owning master is down, any other master can drive the rotation on. If it
died before another master fetched the new key, nothing else holds that key: the finish says so, so
abort on another master and start a new rotation. If another master already holds the key, remove the
dead owner (`hearth cluster remove`) and finish on that master.

**After the finish:**

- **An agent that was offline throughout is cut off** and has to enroll again, with a new token.
- **A member that comes back after a rotation finished without it** stops taking part, with a log line
  saying so: remove it, wipe its data dir and join it again.
- **Browsers and phones** that trusted the old CA must trust the new one: fetch it again from
  `http://<hub>:<port>/ca.crt` (see [HTTPS for the web UI](https.md)).
- **Enroll and join tokens** made before the finish name the old CA and stop working: create new ones.
- **Backups taken before the finish still hold the old key** if they were taken with it. A backup taken
  during the rotation holds both CAs and restores as such: finish the rotation on the restored hub
  before the others join again (see [Restoring a cluster](backup.md#restoring-a-cluster)). Destroy the
  old ones if the key's leak was the reason to rotate.

What a rotation does not undo: until the finish, whoever holds the old key can still pose as a hub to
browsers and agents and mint certificates the cluster accepts for agents (not for members: those must
match the certificate pinned when the rotation started). A leaked database also leaked the Kubernetes
and Proxmox credentials sealed in it: rotate those at their source, as re-sealing them with a new key
does not make the leaked copies useless.

The commands are policy actions run by the local admin or the web UI, `cluster.ca.rotate`,
`cluster.ca.finish` and `cluster.ca.abort` (dangerous), and audited. A member fetching the new key or a node certificate of
the new CA is the action `cluster.ca.fetch_key`, decided and audited by the master that serves it,
refusals included (at most one entry a minute per caller for refusals before the decision, counting
those left out).

To replace the CA of a cluster of one without a rotation, delete `ca.crt` and `ca.key` and enroll every
agent again.

## CLI on a member's host

`hearth token create`, `hearth device revoke`, `hearth admin set-password`, `hearth cluster token
create`, `hearth cluster status`, `hearth cluster promote|demote|remove` and `hearth cluster ca
rotate|finish|abort|status` work on a member's host while its hub runs: they go through the hub's
local control socket, and the running hub decides them. With the hub stopped they refuse, since
writing the local database directly would diverge from the cluster. Commands that create tokens or
change roles run on a master's host.

## Policy and audit

Every action is decided and audited by the master that received the request, exactly as on a single
hub. Replication between members is not an action: a member authenticates with its own hub node
certificate (never with a device or admin credential), and rows it sends are merged without a second
decision.

An action's audit entry is written before the action runs, so a master that cannot place it on two
replicas refuses the action, and says why. Agent heartbeats, the check of a signed-in session and what
the web UI reads write no audit entry, so this refusal does not affect them.

An action that was already running when the replicas went keeps the entry reporting how it ended. The
same goes for a held request that ends in a denial. The hub keeps that entry in the `audit-spool`
folder of its data dir and writes it once the replicas are back, also after a restart. The entry keeps
the time it was made and lands only once. If a spooled entry cannot be read back, the hub writes an
`audit.entry_lost` entry in its place, so the gap shows in the audit log.

## Design notes

- **Trusted members, crash faults.** Every hub belongs to one owner, runs the same binary and shares
  one CA, so a compromised hub is a security incident (revoke it and rotate the CA), not a voting
  problem. The cluster tolerates crashes and splits, not members that lie: no Byzantine fault
  tolerance.
- **No leader.** A leader-based cluster stops writing on the side of a split without a majority. A
  homelab's split is usually a switch or a Wi-Fi link, and both sides still have devices to run, so
  Hearth keeps both sides writing and merges, and limits what a cut-off side may do instead
  (fail-closed dangerous actions, deny-wins revocations, master-owned tokens).
- **Rows, not commands, are replicated.** Each write becomes row changes stamped with an HLC, merged
  per row. Global uniqueness that a shard cannot check is avoided by design: rows such as Kubernetes
  and Proxmox connections take ids derived from their unique name, so two masters creating the same
  one converge to one row.
- **Agents stay small.** The `node` role links no gossip or replication code at idle.

## Limits

- **A removed master's data dir still holds the CA key.** Removal cannot take it back: whoever has that
  data dir can still mint certificates the cluster trusts until you [rotate the hub CA](#rotating-the-hub-ca).
  Wipe the data dir of every removed master. Storage-only members never hold the key.
- **One way schema upgrades:** no downgrade once the cluster has written a newer schema.
- **Metric triggers without Prometheus** read agent metrics from the owning master's memory, which
  holds only the agents streaming to it, so devices on other masters are not evaluated
  ([#261](https://github.com/gvart/Hearth/issues/261)). Prometheus-backed metric triggers are
  unaffected.
- `hearth` commands run on a member's host (`hearth token create`, `hearth cluster token create`) are
  not refused when that master is cut off: the 60-second fail-closed rule covers the hub's API, agents,
  MCP and automations.
- An approval link opens on the master that owns the approval. With `approval_notify.url` set to one
  fixed address, a link for an approval owned by another master answers 409 `not_owner`, naming the
  master to open it on.
- **Single-core hubs and old password hashes.** Admin password hashes set before
  [#94](https://github.com/gvart/hearth/issues/94) use four argon2 lanes, and checking one on a slow
  single-core hub (Pi Zero, Pi 1) can stall it for seconds during a login. Run `hearth admin
  set-password` once after upgrading to re-hash with one lane.
