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
hubs use to reach that hub's TLS port, so it must resolve from your devices. Without `--host`, each
hub's certificate names its own hostname and private LAN IPv4 addresses, and agents and the other
hubs reach its TLS port at its first LAN IP (a hostname with a dot, other than `.local`, comes first
instead). `--cluster-advertise host:port` is the address the other members dial for the cluster port.
Without it a hub advertises, on its `--cluster-listen` port, the first of: the `--cluster-listen`
host when it is a specific address, the first `--host` that is not loopback, its first private LAN
IPv4 address, and last its hostname. A LAN IP rather than the hostname, because a bare hostname
such as `raspberrypi` often does not resolve on the other hubs. Every member listens on the same cluster port: a hub finds the
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
hearth cluster token create --hub-url https://hub-a.lan:7443 [--roles storage,master]
```

Or click **Add hub** on the **Cluster** page of a master's UI (`POST /api/v1/cluster/tokens` with
`{"ttl": "15m", "roles": ["storage", "master"]}`): it confirms what the token lets a new hub do, asks
for the admin password again, then shows the token once, inside the command to copy. Both ways are
the policy action `cluster.token.create` (dangerous, by `admin` or `web`), audited with the TTL and
the roles and never the token, which is stored only as a hash, with its roles, and cannot be shown
again.

The token grants `--roles` (default `storage,master`): a hub that joins with it takes the roles both
the token and its own `--allow-roles` allow, and is refused when that leaves neither storage nor
master (the token is spent all the same). The join command sets `--allow-roles` to the token's roles
when they are not both. The join is the policy action `cluster.join`, audited with the token's roles
and the roles granted.

It prints the token and the command for the new hub. The token is single use and short lived, and
belongs to the master that created it: join through that master. On the new hub, with an **empty**
data dir:

```sh
HEARTH_JOIN_TOKEN=hearthj1.… hearth hub --join https://hub-a.lan:7443 \
  --host hub-b.lan --cluster-advertise hub-b.lan:7444
```

The new hub pins the CA by the fingerprint in the token and gets a hub node certificate and its
roles. It gets the CA's private key only when granted `master`, that is when both the token and its
`--allow-roles` allow it; any other hub holds the CA certificate only and serves no API, UI or agent
port. A storage-only token never yields the CA key, whatever the joining hub asks for. Treat a join
token that grants master like the CA key.

Then the hub finds the cluster by gossip. `--cluster-seeds` (env `HEARTH_CLUSTER_SEEDS`) adds
`host:port` cluster addresses of other members to find it by; the `--join` hub's is added on its own.
Each hub also keeps the cluster address of every member it learns (`cluster/gossip-seeds` in its
data dir) and finds the cluster by them after a restart. An address follows its member when it moves,
and a removed member's goes; a member that is only down, or stopped, keeps its address, so hubs back
from a power cut still find each other. Until a joining or restarted member has found another member, it refuses critical writes (503)
rather than keep their only copy; if none is reached within 30 seconds it starts alone and says so in
its log. It imports its configuration files only once it has found the cluster and caught up, so it
takes the cluster's documents instead of its own.

The new hub's Hearth must support the schema the cluster has written: the same version as the
cluster or a newer one (see [Upgrading Hearth](#upgrading-hearth)). An older one is refused.

### Auto hubs: a device becomes a hub when you add it

You rarely need a join token by hand. **Add device** with **This device may become a hub** ticked
(the default; `POST /api/v1/tokens` with `{"hub": true}`, or `hearth token create --hub`) makes an
enrollment token that also lets the device join the cluster. Ticking it asks for the admin password
again, and is the policy action `cluster.token.create` (by `web` or `admin`), audited with the roles
it may grant; the token also creates the device as usual (`token.create`). Until a device uses
it, revoking it (`hearth token revoke <id>`, or **Revoke** under **Unused enrollment tokens**, with
the password again) stops it for good: see
[Revoking an enrollment token](security.md#revoking-an-enrollment-token).

When such a device enrolls, its installer says what it is: its OS, architecture, memory and free disk.
Only Linux on amd64 or arm64, with at least 1.5 GiB of memory and 2 GiB free on the disk of the hub's
data dir, is offered a hub; a Mac, an armv7 board or a Pi Zero stays an agent. For a capable device
the master mints a join token for it, as the policy action `cluster.token.create` by the enrollment
token (actor kind `token`, target the new device; audited, refused while the master is cut off),
valid 15 minutes and bound to that device. The installer writes it to `/var/lib/hearth/hub/join`
(0600) and installs a `hearth-hub` systemd service, `hearth hub --join-file
/var/lib/hearth/hub/join`, which joins once, deletes the file, and from then on runs as an ordinary
hub; the device keeps its agent too. `--agent-only` on the install command keeps a capable device an
agent, and on a device that is a hub already it stops and removes the `hearth-hub` service (the hub's
data dir stays until `--purge`; remove the member from the cluster as for any hub). The
`device.enroll` audit entry says whether the device's join token was minted, with its roles, or
refused and why.

The cluster stays small:

| Hubs already in the cluster      | A new capable device becomes |
| -------------------------------- | ---------------------------- |
| fewer than 3 masters             | storage and master           |
| 3 masters, fewer than 5 storage  | storage only (no CA key)     |
| 5 storage members                | nothing more: it stays an agent |

The counts include members that are down (not removed), join tokens minted and not yet used, and hubs
that joined with such a token in the last 10 minutes and are not in the gossip yet (until they are
removed), and `cluster.join` checks them again when the device joins, one join at a time on a master: a device whose token allowed master but finds 3
masters by then joins as storage only (audited `capped`), and one that finds 5 storage members is
refused and stays an agent. Promote or demote by hand as before; the caps only bound what happens on
its own. When a master is removed, a storage member that joined this way is promoted to keep 3
masters (see [Keeping 3 masters](#keeping-3-masters)).

A join file the hub cannot use for good (a spent, expired or refused token) is deleted and the
device stays an agent, with a log line saying why; an unreachable master is tried again until the
token expires. Without a join file and without a cluster, `hearth hub --join-file` exits at once,
so the service never forms a cluster of its own.

### A device's page: make it a hub, or agent-only

Each device's page in the UI has a **Hub** card: the cluster member the device became, with its roles
and state, or **agent only** when the hub service is not installed. The device and the member are
linked by the join recorded on the device's join token (the one minted at its enrollment, or the one
below), while that hub's certificate is not revoked; a hub joined with a hand-made join token (`hearth
hub --join`, Add hub) shows no device. `GET /api/v1/devices/{id}/hub` answers the same, with the
counts against the caps, and `hearth device hub <device-id>` prints it on a master's host.

- **Promote and demote** the device's hub there as on the Cluster page (`cluster.promote`,
  `cluster.demote`). A promotion to master asks for the admin password again, on both pages: it hands
  the member the CA key.
- **Make this device a hub** is how a Mac, or any enrolled agent, becomes a hub later: auto hubs are
  Linux only. It asks for the password again and mints a join token for the device
  (`POST /api/v1/devices/{id}/hub`, the policy action `cluster.token.create` by `web`, target the
  device, valid 15 minutes), with the same caps as an enrollment: storage, and master while fewer than
  3 masters are counted; refused (`hubs_full`) with 5 storage members. The page shows a command to run
  on the device:

  ```sh
  curl -fsSL <hub>/install.sh | HEARTH_JOIN_TOKEN=<token> sh -s -- --make-hub https://<master>:7443
  ```

  It re-runs the installer, which keeps the agent and its identity, checks the device (64-bit Linux or
  macOS, 1.5 GiB of memory, 2 GiB free; `hearth agent make-hub`), writes the join file and installs the
  hub service next to the agent: `hearth-hub` on Linux, the launchd job `dev.hearth.hub` on macOS
  (logs in `/var/log/hearth-hub.log`). The device shows as a hub once it has joined.
- **Make agent-only** removes the device's hub from the cluster (`cluster.remove`: refused for the last
  master or storage member, and by the hub you are using; open another master's UI for that one) and
  shows the re-run that stops and removes its hub service, `install.sh --agent-only`. The hub's data
  dir stays; delete `/var/lib/hearth/hub` before making the device a hub again (`make-hub` refuses a
  data dir that holds a hub). A removed master's data dir still holds the CA key: see
  [Limits](#limits). Taking a master away below `--keep-masters` may make a master promote another
  hub-eligible storage member: lower `--keep-masters` first to run fewer masters.

**Away too long.** Deleted rows are forgotten after 7 days. A member that has not reached the cluster
for longer refuses to start with its old data, so it cannot bring deleted rows back: clear its data
dir and join it again.

## How data is kept

- **Placement.** A consistent-hash ring over the `storage` members places each row on `--replicas`
  members (env `HEARTH_REPLICAS`, default min(2, storage members), never below 1). Rows that belong
  together stay together: a device's certificates with the device, runs with their automation, an
  action's audit entries with each other. Small global tables (the admin password, hub
  certificates, configuration documents, device capability ceilings and plugins, Kubernetes and Proxmox
  connections, network hosts, telemetry settings) are on every storage member and every master. The
  tables whose rows grant access (sign-in sessions, MCP and dashboard tokens, panels and their share
  links), and runbook runs, which only masters run, are on **every master and on no storage-only
  member**: see [Who may write what](#who-may-write-what).
- **Writes.** Audit entries, certificates, revocations, tokens, approvals and configuration
  documents are **critical**: they need W = min(2, N) replicas and fail at once with 503
  `cluster_unavailable` when fewer are reachable. The rows only masters hold need no quorum. A sign-in,
  a new MCP or dashboard token, a panel or a share link is written on the master that runs it and sent
  to the other masters, each of them that is down (or left the gossip) getting it from a hint, so any
  one master signs in alone, one of two included. A sign-in on a master that dies before another has it
  is lost: sign in again. A sign-out, a token or link revocation and a password reset need no quorum
  either: each only takes access away, so it is applied on the master at once and sent to every other
  master, trying one that does not take it for up to 3 seconds before it hints it. The answer says
  how many masters took it ("applied on 1 of 2 masters; the others get it when they are back"), in the
  web UI and the CLI: until the others do, a master that dies first loses it, and it must be done again.
  A password reset also raises a session epoch on the admin row (two resets keep the higher), and a
  session created before it is ended on every master as the reset reaches it, the sessions that master
  alone held included. A sign-out of a session the master does not hold writes its deletion all the
  same, and a deletion wins over any copy of the session created before it, whatever the clocks of
  the masters. Revoking an MCP or dashboard token or a share link the master does not hold writes a
  revoked stub of it, and the token's own copy, from the master that has it, merges into a revoked
  one. Runbook runs need more: a strict **majority of the masters** (W = M/2 + 1 of the M masters,
  down ones included; a storage member never counts, and a member that says it is a master counts
  only once it proved the hub CA key), both to read the run and to save it, so runbooks are
  consistent rather than available across a split (below). Other writes (presence, facts, scans, automation run
  history) need one replica and reach the others in the background. A replica that is down is replaced by the
  next live member, and gets the write later from a hint (kept in `hints.db`, bounded).
- **Reads.** A read by key goes to the nearest live replica (R = 1). When that replica has no copy of
  the row at all (it missed the write while it was down), an approval or approval link, device or
  device route is asked of every live replica, and the newest copy wins, a deletion included. A device
  certificate check always asks every live replica, and a revocation any one of them holds wins, however
  new the others' copies are ([#387](https://github.com/gvart/hearth/issues/387)); with none reachable,
  the agent's call answers 503 and it retries. A certificate's recorded fingerprint (its pin) is read
  from every live replica too: a replica without one is behind and the others decide, but two replicas
  that record different fingerprints decide nothing, and the certificate is neither renewed by a hub
  CA rotation nor taken as matching. A fingerprint is set once: a later version naming another does
  not replace it on merge, and two different ones merge into a conflict that stays.
  A master reads a sign-in session, an MCP or dashboard token, a panel, a share link and a runbook run
  on its own copy, and never asks another member. A master that started, or was just promoted, first compares
  these rows with every other live master that proves the hub CA key, so it holds every sign-out and
  reset they took while it was down: until it has (a moment: it tries as the first check comes, then
  in the background, backing off; a check that comes while one runs does not wait for it), a sign-in,
  MCP or dashboard token check or a share link answers 503 `cluster_unavailable`, the session cookie
  is kept and the UI retries. A hub that never had another hub reads its own copy at once. One that
  did (the hub certificates of more than one hub are recorded, those of a hub removed since included)
  and finds no other master live waits 30 seconds for the gossip to find one, then reads its own copy,
  logs a warning and shows a banner in the web UI: "This hub could not compare sign-ins with another
  master." That is the AP trade-off: a master cut off from the others keeps signing in rather than
  stop, so a sign-out, a revocation or a reset taken only by masters it cannot reach is not in force on
  it until one of them is back. The banner goes once it compared with one. A list asks every storage member and merges the answers. A stale copy a read sees is repaired.
  A write that depends on rows it reads first copies their newest version from the other live members. These
  writes are pinning or revoking a device's certificates, revoking hub certificates, consuming a token or
  approval link, deciding an approval, signing out, a password reset, revoking an MCP or dashboard token
  or a panel link, deleting a panel (its links), starting or advancing a CA rotation, the first import or a delete of configuration
  documents, and saving a runbook run; for the rows only masters hold, the copies are read on the other
  masters only. A member
  that missed a pin, a certificate, a decision or a session while it was down still decides on the newest copy.
  A password reset ends every session: the master running it first reads every session the other live
  masters hold, and the session epoch it raises ends those it still misses.
  A runbook run is saved only from the version it was read at, on the first live master (by name) that
  proves the hub CA key, so of two saves from one version (two masters, or a master and an operator)
  exactly one is taken. A master whose save is refused so reads the run again from the masters.
  Members compare digests of the rows
  they share and copy what differs (anti-entropy), so replicas converge after an outage or a split.
- **Runbook runs across a split.** Everything else keeps writing on both sides of a split; runbook runs
  do not. Starting a run and recording each step (as running before it runs, then its outcome) need a
  majority of the masters to read the run and to take the save, and two majorities always share a
  master, so at most one side of a split records a step and no step runs twice. On the side without
  that majority the start, or the step, is refused before anything runs or is written, with 503
  `cluster_split`: "cluster split: runbook steps need a majority of masters; retry when the cluster
  heals". A run there waits (its master logs the same reason) and goes on once the split heals; a step
  already running when the split came, whose outcome could not be recorded, stops the run as `unknown`
  for an operator to decide, as when its master dies. A hub that started without reaching any member
  it knows also refuses runbook runs until it finds one. The count is of masters, not of storage
  members or `--replicas`: one master alone runs runbooks; with two, both must be up, so one of them
  crashed or cut off stops every run; run three masters for runbooks that keep going with one master
  down. A master that is stopped cleanly leaves the gossip and is off the count until it is back, like
  a storage member off the ring. Promote, demote or stop one master at a time, so that the majorities
  before and after a change still share a master. The re-sealing of runs during a
  [hub CA rotation](#rotating-the-hub-ca) needs the same majority: `hearth cluster ca finish` fails
  until it is reachable, and can be run again.
- **Conflicts.** Every row carries a hybrid logical clock (HLC) stamp and the member that wrote it.
  Two writes to the same row merge by **last writer wins** on that stamp. Some rows do not merge this
  way: the audit log is append-only (entries are only ever added); a revocation, once any replica has
  it, is never cleared by a later write (deny wins); and a token, an approval or an approval link is
  decided only by the master that owns it (below).
- **Clocks.** A member refuses a stamp more than 60 seconds ahead of its own clock, so a host with a
  wrong clock cannot win every conflict. Keep the hosts' clocks in sync (NTP).

### Who may write what

Members send each other rows in a few ways: the coordinator of a write sends the rows it wrote to the
other replicas, or keeps them as hints for one that is down; a master that is not a replica of a key
asks a replica to coordinate the command (`apply`); anti-entropy and a promoted member's catch-up pull
and push the rows that differ; a storage member being demoted hands its rows off; a read repairs the
stale copies it saw; and a revocation is fetched from the member the gossip names.

The roles a member announces on the gossip are its own word, so they decide nothing here. What decides
is the hub CA key, which only masters hold: on each replication connection, each end that holds it
signs the connection's TLS exporter with it.

- **Global rows come from masters only.** A member refuses a merge with a global row from a peer that
  did not prove it holds the key, and drops the global rows it fetches from one (anti-entropy, catch-up,
  read repair, a revocation, a backup's pull). A member without the key writes no global row and sends
  none: it takes them from the masters. A password reset still runs on every storage member, each with
  the master's stamp, and a master that is not a storage member writes its global part itself.
- **Commands are coordinated for masters only.** A member refuses `apply` from a peer that did not
  prove it holds the key: what it coordinates is written in its own name.
- **Masters call masters only.** The HTTP calls between masters (an agent call forwarded to the master
  holding the device's stream, a role change) are served only to a live master that proved the key
  on the connection, and a master sends one only to a member that proves it too, so a member that
  says it is a master cannot take a device's terminal or exec. A role change goes to the member
  changed, which need not hold the key.
- **Trust follows the gossip.** A proof counts while the gossip says the member is a master: a
  connection opened before a demotion carries no master's call or row after it, and one opened before
  a promotion is replaced.
- **Rows that grant access live on masters only** ([#384](https://github.com/gvart/hearth/issues/384)).
  Sign-in sessions, MCP tokens, dashboard tokens, panels and their share links are global rows, so all
  of the above holds for them, and more: a master sends them only to a member that proved, on the
  connection and before they go, that it holds the key; a member without the key drops any it is sent,
  and deletes those it holds when it starts or is demoted from master; a master answers a fetch, a read
  that names these tables, or a comparison of their digests only to a master that proved the key; and a
  master checks a session or a token on its own copy, never asking another member. The rows a master
  withholds from a member that did not prove the key stay in that member's hints, for a connection on
  which it does: no more than 1000 hints or 8 MiB of them per member, and none after it answered 20
  times without a proof since its last one (anti-entropy brings the rows to a master that proves it
  again). A read another member sends without proving the key runs under an SQLite authorizer
  that allows only a `SELECT` of the replicated tables that are not these: not the database's raw pages
  (`sqlite_dbpage`, `dbstat`), its schema or a pragma, however the query is written. Anti-entropy of the
  sharded rows, the global rows or these takes no row of another kind's tables. A storage-only member
  neither holds nor serves them, so it cannot forge a sign-in, an MCP or dashboard token or a share
  link, nor answer "yes" to one. A member promoted to master compares them with every live master that
  proves the key before it reads them.
- **Runbook runs live on masters only** ([#387](https://github.com/gvart/hearth/issues/387)). A run's
  state says which step a master runs next, so the runs are master rows like the above: a storage-only
  member neither holds nor serves them, cannot start or save one (it holds no key, and a master takes
  no command, row or hint of them from it), and is not among the masters a run's majority counts, even
  when it says on the gossip that it is a master: a master sends a save to decide only to a master that
  proved the key on the connection, and counts a read or an ack only from one.
- **Sharded rows go through storage members.** They are their replicas: a storage member coordinates
  the writes a master forwards, keeps hints, hands rows off and runs anti-entropy for them.

So a storage-only member, compromised, cannot change the admin password, the configuration (policy,
automations, runbooks), a device's capability ceiling or plugins, the hub certificates or the
integrations, cannot sign in or forge a token or a share link, and cannot change which step of a
runbook run a master runs next. It can still change the sharded rows
it holds, or answer reads of them as it likes, until they are signed by the master that wrote them
([#387](https://github.com/gvart/hearth/issues/387)). For the rows of the buckets it is a replica of
(with `--replicas 2` and S storage members, about 2 in S of them), it can:

- **Refuse a device certificate**: a certificate check asks every live replica and refuses the device
  if any one answers "revoked", so a storage member can make a master refuse a device whose
  certificate it holds (until it is removed from the cluster). It cannot un-revoke one: its "not
  revoked" or "no such certificate" does not outweigh a revocation another replica holds, and a
  revocation, once merged, is never cleared. It decides alone only while it is the one live replica of
  the certificate's row that answers. Hub certificates are global, so none of this reaches hubs.
- **Spoil a certificate's pin**: a fingerprint read asks every live replica, and replicas that record
  different fingerprints decide nothing, so a storage member can answer with another and have a hub CA
  rotation not renew that device's certificate (it must enroll again), as a disagreement is never
  taken for a match. It cannot have a certificate minted with the CA key taken as the one recorded
  for its serial, nor hide a recorded fingerprint by answering with none, nor replace one by sending a
  newer version (a fingerprint is set once; two different ones merge into a conflict). It can set the
  fingerprint of a certificate that has none yet, one issued before fingerprints were recorded and not
  pinned since, and it decides alone while it is the one live replica that answers.
- **Hide, change or invent audit entries**, and the devices list, device facts and presence, device
  routes, and automation run history of its buckets: what the UI and the API show of them.
- **List forged enrollment tokens, join tokens or approvals**. They grant nothing: their owner acts on
  its own record of them (below).

Tokens and approvals are sharded too, but the master that creates one keeps a record of it in its own
data dir: it refuses a token, join token, approval or approval link it has no record of, and what a use
grants (a join token's roles, an enrollment token's hub roles and labels, a link's approval) comes from
the record, not the row. A held action acts on an approval only if its owner approved it. So a storage
member cannot mint a join token that grants master (and so the CA key) or approve an action.

A critical global write (the admin password, the configuration, a ceiling, a certificate) needs, while
another master is live, the ack of a master that proves the key: the storage members never hand a
global row on. A member that acks it without a proof is no master and does not count. A master is
demoted, and deletes its key, only once another master took its global rows and no hint of one waits
for a master. A master is safe to stop, as to the global rows, once another master is caught up; and a
hub starting, or catching up after a promotion to storage, compares the global rows with a live master
before it counts as in sync. `HEARTH_ADMIN_PASSWORD` is applied only once a master is in sync.

**Upgrading.** A member of a version from before these checks proves nothing: upgrade every hub
together. The owners' records start empty, so enrollment tokens, join tokens and pending approvals made
before the upgrade are refused: create new ones. Device ceilings were sharded before; a master may lack
one that only storage-only members hold. A change of such a device's ceiling is measured from none, so
any raise asks for the password again, and it is refused until the device's agent reports its ceiling.
Admin commands (`hearth admin set-password --data-dir` and the others) refuse to run on a storage-only
member's host, before anything is written: run them on a master's. Runbook runs were sharded before
([#387](https://github.com/gvart/hearth/issues/387)): a storage-only member deletes its copies when it
starts, and the masters compare theirs before they read them, so a run that only storage-only members
held is gone. Let the runs finish, or stop them, before you upgrade a cluster with storage-only
members.

## Masters

- **Every master serves agents.** An agent streams to any master. It gets the list of masters when it
  enrolls and on every connect, and while it streams its master pushes the new list whenever the
  masters change (a couple of seconds after they settle, and again within 30 seconds if a new master's
  URL is recorded late). It keeps the list in `hubs` in its data dir, and moves to another master, with
  the usual backoff, when its master goes away: an agent streaming to the first hub since before the
  others were masters still finds them when that hub stops. The master holding a device's stream records it (a
  `device → master` route); an exec, probe, Docker call, scan, built-in metric read, log stream or
  terminal for that device on another master is forwarded to it over the members' mutual TLS. For an
  exec, probe, Docker call or scan, the decision and the audit entry stay on the master that got the
  request; a log stream or terminal is proxied whole and decided on the holder. If the holder cannot
  be reached, the call fails with "agent not connected" until the agent has moved; one lost after it
  was sent has an unknown outcome.
- **Presence.** The master holding a device's stream marks it online and offline. A device with no
  live stream is marked offline by the master that owns it on a hash ring over the live masters, once
  that master has owned it for 30 seconds.
- **Automations and loops.** An automation's schedule, check and metric triggers run on the master that
  owns it on the same ring, as do runbook runs and the expiry of pending approvals; when a master
  dies, its share moves to the others. Device and network-discovery triggers fire on the master where
  the event happens (the one holding the device's stream, or running the scan), and a manual run on
  the master it is asked of: each event happens on one master, so an automation fires once. Rows
  copied from other members raise no automation events. Each master keeps the
  [built-in metrics](prometheus.md#built-in-metrics) of the agents streaming to it, so without
  Prometheus a device metric trigger reads the device's value from the master holding its stream,
  over the masters' link; while that master is down there is no value, and the trigger does not fire.
  Network discovery, the DHCP/Pi-hole import,
  scheduled backups, telemetry and the [`hearth.local` announcement](#the-ui-on-any-master) run on
  one master each; Beszel and Talos reads on every master. During a split both sides may run one:
  accepted.
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
outcome on the master asked, and refused by a master that is cut off. A promotion to master from the
UI asks for the admin password again. Ask a master: on the **Cluster** page of its UI (members, roles,
allowed roles, state and progress) or a device's page (its hub's roles), its API
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
- **Removed automatically.** A member down for `--member-dead-after` is removed the same way, by a
  master on its own (see [A hub that stays down](#a-hub-that-stays-down)).
- **Promoted automatically.** When fewer than 3 masters are left, a master promotes a storage member
  that joined as a hub-eligible device to master the same way (see
  [Keeping 3 masters](#keeping-3-masters)).

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
members stay listed until this hub restarts; a member down shows when it is removed automatically
(`dead, removed automatically in ~5h`, and on the Cluster page). A line under the table names the members whose host flags
differ (see [Host flag drift](#host-flag-drift)). In the hub log, `caught up with the cluster` marks
a member that is ready after a start. A line above the table says whether this hub is
[safe to stop](#is-it-safe-to-stop-this-hub).

### Is it safe to stop this hub?

You started Hearth on a laptop, added hubs on other devices, and now want to shut the laptop. There is
no handoff step: the hub you want to stop tells you whether stopping it now loses anything. Run
`hearth cluster status` on its host, or open the **Cluster** page on it:

```text
Safe to stop this hub:  yes
```

It is safe when both hold:

- **Every row this hub holds has a copy on another live storage member that is caught up.** A storage
  member is caught up when it is live, is not still copying its rows after a promotion (`syncing`),
  no hint waits for it on this hub, and its last anti-entropy round with this hub, on the current ring,
  compared every bucket both hold and copied what differed. Rows this hub holds for buckets it does not
  own (written before the others joined) must have been handed off to their owners.
- **Another master is live**, so something still serves the UI, the API and the agents.

Otherwise it says what is missing, for example:

```text
Safe to stop this hub:  no
  - no other master is live: nothing would serve the UI, the API or the agents; promote another hub to master
  - replica hub-b has not finished an anti-entropy round with this hub yet; until it catches up, this hub
    holds the only up-to-date copy of the rows in 812 buckets
```

The reasons are `no_other_master`, `only_copy` (no other storage member holds some rows: add one or
promote one to storage), `replica_behind` (with the member: down, syncing, hints waiting for it, or no
anti-entropy round yet), `hand_off` and `writes_in_flight`. `--json` and `GET /api/v1/cluster/members`
carry them under `safe_to_stop`.

A hub that has just joined counts as catching up until its first anti-entropy round with this hub, which
runs every 30 seconds: wait for the green line. A single hub is never safe to stop, as it holds the only
copy of everything and is the only master. The check counts rows by shard bucket (65,536 of them), not
one by one, and trusts a successful anti-entropy round until the ring changes, the round fails or the
member is found down. A write another master sent to a member that went down for a moment waits as a
hint on that master, not on this hub.

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
- **A hub stays down.** After `--member-dead-after` (24 h) a master removes it, if it sees a majority of
  the members (see [A hub that stays down](#a-hub-that-stays-down)); if it was a master, a hub-eligible
  storage member takes its place (see [Keeping 3 masters](#keeping-3-masters)).
- **A hub restarts.** Until it has caught up with the cluster, its API waits up to 5 seconds per request
  and then answers 503 `catching_up`; the UI shows the error and works again once the hub is ready.

CI holds the cluster to these: an end-to-end test (`task e2e:cluster`) runs hubs and an agent in
Docker Compose, kills a master and a storage member, splits the cluster and heals it, and fails if any
step takes longer than its stated bound.

## A hub that stays down

A member down (dead or left) for `--member-dead-after` (env `HEARTH_MEMBER_DEAD_AFTER`, default `24h`) is
removed automatically, exactly as `hearth cluster remove` does: its hub certificates are revoked, every
member drops it, and the others re-copy the rows it held. One master does it (the owner of the
`dead-members` loop on the ring of masters), as the `cluster.remove` policy action by the hub (actor
`hub`, its node ID), audited with the reason (`down for 24h`) and when the member went down. It follows the
policy's modes for dangerous actions: `classes: {dangerous: confirm}` holds each removal for approval,
`deny` refuses it (refused removals are tried again an hour later). `--member-dead-after 0` turns it off.

- **Only a majority removes.** A master removes only while it sees a strict majority of the members it
  knows alive, the down ones counted. The minority side of a split never removes, and neither does a
  cluster of two whose other member is down: remove that one by hand. A side that keeps the majority
  through a split longer than `--member-dead-after` removes the others; they rejoin as below.
- **Never the last master or storage member.** A member down whose removal would leave no live master,
  or no live storage member, stays, and the master logs once why.
- **A member that comes back starts over.** Every member records since when each other member is down
  (`cluster/down-members` in its data dir), so a restart of the master does not reset the timers; a member
  seen alive again is dropped from the record. Time a hub itself was stopped for longer than 10 minutes is
  not counted: its timers start again when it is back.
- **A removed hub that comes back is refused.** Its certificates are revoked, so no member accepts it,
  and it logs once: `the cluster's members refuse this hub's certificate: it was most likely removed`.
  Stop it, wipe its data dir and join it again with a new join token, as in
  [Replacing a dead hub](#replacing-a-dead-hub).

`hearth cluster status` and the Cluster page show, for a member down, roughly when it is removed. A
master that is due to remove one but may not (no majority, the last master or storage member) logs
`a member is down for longer than --member-dead-after but is not removed`, with the reason.

## Keeping 3 masters

When a master is removed (by hand or after `--member-dead-after`) and fewer than `--keep-masters` (env
`HEARTH_KEEP_MASTERS`, default `3`) masters are left, a master promotes a live storage member to
master, exactly as `hearth cluster promote <member> master` does: the member fetches the CA key from
that master over the pinned `FetchCAKey` channel and starts serving. One master does it (the owner of
the `keep-masters` loop on the ring of masters), as the `cluster.promote` policy action by the hub
(actor `hub`, its node ID), audited with the reason (`keep 3 masters`). It follows the policy's modes
for dangerous actions: `classes: {dangerous: confirm}` holds the promotion for approval, `deny`
refuses it (a refused promotion is tried again an hour later). `--keep-masters 0` turns it off; it
cannot be more than 3, the cap on the masters devices become on their own.

- **Only a hub-eligible device.** A member is promoted only if its latest join used the join token
  minted for it when it enrolled with a token marked **This device may become a hub**: you agreed then
  that it may hold the CA key, and it was checked capable. A hub that joined with a join token from
  `hearth cluster token create` or **Add hub** is never promoted on its own; promote it by hand. The
  member must also be `alive`, a storage member that is neither syncing nor draining, and allow master
  in its `--allow-roles`.
- **Which one.** The eligible member that joined first, then the lowest node ID: every master picks
  the same. One at a time: the next promotion waits until the gossip shows the last one as master.
- **A master counts until it is removed.** A master that is down, or that left because it was stopped,
  still counts, so restarting a master promotes no one. Masters on their way count too (a hub joining
  with a token that grants master, a minted join token not yet used), so the cluster never has more
  than 3 masters this way.
- **Only a majority promotes, never during a CA rotation.** As for removals, a master promotes only
  while it sees a strict majority of the members it knows alive; and not while a
  [hub CA rotation](#rotating-the-hub-ca) is under way.
- **Demoting by hand.** A master you demote below `--keep-masters` may be replaced by an eligible
  storage member: to run fewer masters, lower `--keep-masters` on the masters first.

A master that is short of masters but promotes no one (no majority, no eligible member) logs
`fewer masters than --keep-masters, but none is promoted`, with the reason.

## Replacing a dead hub

Remove it (or let the cluster do it after `--member-dead-after`), then join a new one:

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

Open `http://hearth.local:7080` (or `https://hearth.local:7443` once the CA is trusted): one master
answers mDNS queries for `hearth.local` with its LAN IP, and every master's certificate names it. Logins,
token creation and everything else work on every master, with any other master down. Sessions are on every master and cookies belong to
the host name, which stays `hearth.local` when another master takes over, so a login survives a
failover: reload the page.

- **Takeover.** The master owning the `lan-name` key on the ring of live masters announces the name.
  When it stops cleanly it says goodbye and another master answers within a couple of seconds; when
  it dies, within about 10 seconds (the time the others take to find it dead). Records carry a
  10-second TTL and every new announcement flushes the old address from caches, so a browser
  reaches the new master within about 20 seconds at worst.
- **Joining.** A master that joins may take the name over; it answers once it has caught up with the
  cluster (usually within a second), and until then nobody may.
- **Every master or none.** Whichever master owns the name announces it, so set `--no-lan-name` on all
  masters or on none. A master that cannot announce on the LAN (in Docker's default bridge network,
  say) leaves the name unanswered while it owns it: run it with `--no-lan-name` or `--network host`.
- **Split network.** During a partition each side may have a master announcing the name; a browser
  gets whichever answers it, and both work. It converges when the split heals.
- **Where it works.** mDNS stays on one LAN segment: browsers on another VLAN or over a VPN, and
  devices without an mDNS resolver (some Android browsers), need a master's address or a shared DNS
  name instead. Agents never use `hearth.local`: their addresses come from the enrollment token and
  the list of masters.

Or open `https://<any master>:7443` (or `http://<any master>:7080`). Switching from `hub-a.lan` to
`hub-b.lan` means logging in again; give all masters one shared DNS name (several A records) for one
login across masters off the LAN.

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

**Upgrading to the release with master proofs ([#382](https://github.com/gvart/hearth/issues/382)).**
This one is not rolling: a member of an earlier version proves nothing, so its global writes and its
requests to coordinate are refused. Upgrade every hub together. Enrollment tokens, join tokens and
pending approvals made before the upgrade are refused after it: create new ones. See
[Who may write what](#who-may-write-what).

**Upgrading to the release that keeps access rows on masters
([#384](https://github.com/gvart/hearth/issues/384)).** Not rolling either: stop every hub before you
start any on the new version, in the same step as the one above if you skipped it. As the new version
migrates a database that was a cluster's (it holds the hub certificates of more than one hub), it
deletes the sign-in sessions, MCP tokens, dashboard tokens and panel share links in it, and each hub
drops its hints of them: a copy kept from before may have missed a sign-out or a revocation that only
storage-only members held. This happens once per database, and also when you restore a backup taken
before this version. Sign in again, and create the MCP tokens, dashboard tokens and share links you use
again. Panels stay on the masters that held them; a storage-only member deletes its copies, so in a
cluster with storage-only members a panel that only they held is gone: create it again. A hub that
never had another member keeps everything. A hub that had one, removed since, counts as a cluster's
(the removed member's certificates stay recorded): sign in again there too.

## Node certificates

A hub node certificate is valid for a year. A master renews its own with the CA key, at start; a member
holding no CA key asks a master for a new one while it runs, once its certificate expires within 30
days (the action `cluster.node_cert.renew`, safe, decided and audited by the master). Each member
records its node certificate in the cluster, so `cluster remove` can revoke it.

## Backups

A backup (`hearth backup`, a scheduled one, or **Settings → Backup** in the UI) taken on a master copies
the whole cluster store from the live members, every shard included (the sessions, tokens and panels
from the masters), and is refused while some shard has no live replica. A storage-only member, which
holds no sessions, tokens or panels, refuses to take one. A hub restored from a backup forms a new cluster of one, in a new cluster epoch:
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

`hearth token create`, `hearth token revoke`, `hearth device revoke`, `hearth device hub`, `hearth device capabilities --set`, `hearth admin set-password`, `hearth cluster token
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
  (fail-closed dangerous actions, deny-wins revocations, master-owned tokens). Runbook runs are the
  exception: a step that runs twice cannot be merged away, so they need a majority of the masters.
- **Rows, not commands, are replicated.** Each write becomes row changes stamped with an HLC, merged
  per row. Global uniqueness that a shard cannot check is avoided by design: rows such as Kubernetes
  and Proxmox connections take ids derived from their unique name, so two masters creating the same
  one converge to one row.
- **Agents stay small.** The `node` role links no gossip or replication code at idle.

## Limits

- **Auto hubs are Linux only.** A Mac never offers itself as a hub at enrollment: make it one from its
  page ([Make this device a hub](#a-devices-page-make-it-a-hub-or-agent-only)).
- **A removed master's data dir still holds the CA key.** Removal cannot take it back: whoever has that
  data dir can still mint certificates the cluster trusts until you [rotate the hub CA](#rotating-the-hub-ca).
  Wipe the data dir of every removed master. Storage-only members never hold the key.
- **One way schema upgrades:** no downgrade once the cluster has written a newer schema.
- `hearth` commands run on a member's host (`hearth token create`, `hearth cluster token create`) are
  not refused when that master is cut off: the 60-second fail-closed rule covers the hub's API, agents,
  MCP and automations.
- **Runbooks need a majority.** A runbook run starts and moves on only where a majority of the
  masters is reachable ([Runbook runs across a split](#how-data-is-kept)). The other side of a split,
  and every run while most masters are down, waits until they are back. With two masters that means
  both. The majority is counted on the members a hub knows: one restarted during a split knows only
  those it reaches, and a master that is stopped (not crashed) leaves the gossip and is off the count
  until it is back. Avoid restarting or stopping hubs during a split.
- An approval link opens on the master that owns the approval. With `approval_notify.url` set to one
  fixed address, a link for an approval owned by another master answers 409 `not_owner`, naming the
  master to open it on.
- **Single-core hubs and old password hashes.** Admin password hashes set before
  [#94](https://github.com/gvart/hearth/issues/94) use four argon2 lanes, and checking one on a slow
  single-core hub (Pi Zero, Pi 1) can stall it for seconds during a login. Run `hearth admin
  set-password` once after upgrading to re-hash with one lane.
