# Hub high availability

**Status:** proposal, not scheduled. Out of v0 scope (CLAUDE.md principle 5).

## 1. Problem and goals

Today there is exactly one hub. It owns the SQLite store (`internal/store`), the CA key
(`internal/pki`, `ca.key` at 0600 in the data dir), the agent streams, the offline sweeper
(`Registry.Run`) and the UI/SSE API. If that node dies, enrollment, presence, the UI and every
future automation stop until someone restores it by hand. Agents keep running and retry, but there
is nothing to reconnect to.

**Goal:** the control plane survives the loss of any one hub node, with no lost committed writes
and agents reconnecting automatically.

**Non-goals**

- Multi-tenant or untrusted federation (hubs owned by different people trusting each other).
- Blockchain or BFT consensus. Byzantine fault tolerance protects against nodes that lie, which only
  matters when participants do not trust each other. Every Hearth hub belongs to one owner, runs the
  same binary and shares one CA, so a compromised hub is a security incident (revoke it), not a
  voting problem. Crash-fault-tolerant consensus (Raft) gives "survives node death" with 2f+1 nodes,
  where BFT needs 3f+1, plus signatures on every message and much more complex code, for no benefit
  here. Proof-of-work or proof-of-stake are irrelevant without an adversarial, open membership.
- Geo-distribution or surviving a network partition with writes on both sides.

## 2. Options compared

| | (a) Warm standby | (b) Raft cluster (3 or 5) | (c) Leaderless / CRDT |
|---|---|---|---|
| Recovery time | minutes (scripted or manual promote) | seconds (election + agent backoff) | none (always writable) |
| Data loss on failover | last ~1 s of writes (RPO > 0) | none for committed writes | none, but conflicts |
| Nodes needed | 2 | 3 (tolerates 1) or 5 (tolerates 2) | 2+ |
| Automatic failover | no: 2 nodes cannot tell "peer dead" from "link dead" | yes, quorum decides | yes |
| Complexity | low | medium to high | high, and wrong for our invariants |
| CGO / footprint | none if run as a sidecar; hub binary unchanged | hashicorp/raft + bbolt are pure Go, a few MB on the hub | depends on library |
| Single-use tokens, audit order | safe on one primary; RPO window needs care | linearizable through the log | cannot guarantee |

**(a) Warm standby.** The primary streams its SQLite WAL to a standby or object store
(Litestream-style) and the standby restores from it. Promotion is a script: stop the old primary
(fence it), restore, start `hearth hub`. Two nodes cannot fail over safely on their own, because
a standby that cannot reach the primary does not know whether the primary is dead or just
unreachable; auto-promoting risks two primaries. The human (or script run by the human) is the
tie-breaker. Cheap, and useful even without HA as continuous backup. Litestream itself links a cgo
SQLite driver, so it runs as a sidecar rather than inside the hub; a pure-Go in-process
alternative (periodic `VACUUM INTO` snapshots plus WAL shipping) is possible but is our code to own.

**(b) Raft-replicated hubs.** Every write goes through a replicated log; a leader is elected by
majority, so 3 nodes survive one failure and 5 survive two. Two nodes are no better than one for
automatic failover (losing either loses quorum). Candidates:

- **hashicorp/raft with an FSM applying store writes.** Pure Go, mature (Consul, Nomad). The FSM
  applies typed store commands (`ConsumeToken{hash, now}`, `AppendAudit{...}`, `Heartbeat{id, ts}`)
  to the local SQLite file, not raw SQL strings, so non-deterministic inputs (time, random IDs) are
  fixed by the leader before proposing. SQLite stays the query engine on every node, and reads are
  local. Log store via raft-boltdb (bbolt, pure Go). Snapshots via `VACUUM INTO`.
- **Embedded etcd.** Pure Go and battle-tested, but a key-value store: the SQL store, migrations and
  queries would be rewritten onto KV. Large dependency tree and binary growth. Poor fit.
- **rqlite as library or sidecar.** Closest to what we want (Raft over SQLite), but it links a cgo
  SQLite driver, so it can only be a sidecar. That means a second process and an HTTP SQL API
  instead of `database/sql` transactions. Breaks the single-binary story.
- **dqlite** is excluded: it requires cgo (C libraries libdqlite and libraft), which violates
  `CGO_ENABLED=0`.

**(c) Leaderless / CRDT.** Every node accepts writes and merges later. This breaks two invariants:
a single-use enrollment token can be consumed on both sides of a partition (two devices enrolled
from one token), and "no action without a policy decision and an audit entry" loses its meaning
when a revoked cert or denied action is still accepted by a stale replica. An append-only set of
audit rows merges fine, but a total order and "the decision was durable before the action ran"
do not. Rejected.

**Principles check.** HA lives entirely in hub mode. Agents only gain an endpoint list and a
rotation in their existing reconnect loop, so the < 20 MB idle agent target is unaffected (raft
code is linked into the binary but never initialized in agent mode). It stays one binary with
`CGO_ENABLED=0` under (a) with an optional sidecar and under (b) with hashicorp/raft. A single-node
hub stays the default and must not require any of this (principle 1: adopt, don't replace).

## 3. Hard parts

**CA key.** Today `ca.key` never leaves the hub data dir, and enrollment tokens pin the CA
fingerprint (`hearth1.<secret>.<ca-fingerprint>`).

1. *Replicate the key to every hub.* Fingerprint and agent trust unchanged. But the key now lives
   in N data dirs, which stretches the "never leaves the hub data dir" rule to "never leaves a hub
   data dir". Copy it once, out of band, over mTLS at cluster join, written 0600; never put it in
   the Raft log or snapshots (they end up in backups).
2. *Per-hub intermediate CAs.* A root signs one intermediate per hub; agents pin the root. Each hub
   key stays in its own data dir, and a lost hub is revoked alone. The root key can then be kept
   offline, which is stronger than today. Cost: chain verification instead of a single-cert pin,
   intermediate revocation, and a root-signing step when adding a hub.
3. *Leader-only (or one designated node) signing.* The rule holds literally. Running agents keep
   working through a failover, but enrollment is down until that node returns, so it only half
   removes the single point of failure.

For (a) the standby needs the CA files to take over. They never change, so a one-time copy at
standby setup is enough, and they are not part of WAL streaming.

**Single-use tokens and the audit log.** `Tokens.Consume` is one atomic `UPDATE ... WHERE used_at
IS NULL ... RETURNING`. Under Raft it becomes a log command: the leader proposes, every node
applies the same UPDATE at the same log index, and the caller gets the result from the apply, so
exactly one Consume wins cluster-wide. Audit appends are log commands too; IDs are assigned in log
order, so all nodes hold identical rows, and the append-only triggers still guard each local file.
An action must not run until its audit entry is committed by a quorum. Without quorum the hub
fails closed (deny). Under (a), writes in the RPO window can be lost on promotion: a consumed
token could become reusable. Promotion therefore invalidates every token issued before the
promote, and the gap in the audit log is recorded as an audit entry by the new primary.

**Agent failover.** The agent persists the hub address at join (exact format owned by T5). HA
extends that to a list of hub endpoints, delivered in `EnrollResponse` and refreshed in every
`Welcome` (additive proto fields, minor protocol bump). The reconnect loop rotates through the
list using T5's backoff with jitter. A follower either redirects to the leader or refuses so the
agent moves on. Each hub's server cert carries SANs for its own hostnames and IPs; if a shared DNS
name or VIP is used, every hub cert includes it too. With intermediates (option 2 above) agents
verify the chain to the pinned root.

**Status sweeper.** `Registry.Run` currently runs on every hub process. In a cluster it must run
only on the leader: start it on gaining leadership, cancel its context on losing it. A new leader
also waits one `OfflineAfter` grace period before its first sweep, so agents that are still in
backoff are not all marked offline at once.

**SSE clients and sessions.** The event bus is in-process. If every node publishes events from its
FSM apply, a UI connected to any node sees all changes; EventSource reconnects on its own and the
UI resyncs with a list call. Sessions live in the `sessions` table, so they replicate, but the
cookie is scoped to an origin: a browser switching from `hub-a` to `hub-b` must log in again unless
all hubs share one name (DNS with several records, or a VIP the user already runs).

**Upgrades and schema migrations.** goose currently migrates on `Store.Open`. In a cluster,
followers must not migrate on their own. Rules: migrations stay additive within a release; a
node refuses to join if it cannot apply the cluster's schema version; the leader proposes "migrate
to N" as a log command only after every voter reports support for N; old log entries stay
replayable (versioned commands). Rolling upgrade order: followers first, then the leader by
transferring leadership. Under (a) the standby holds a byte copy and runs migrations only when
promoted; downgrades are unsupported.

## 4. Recommendation

Ship (a) first as a cheap win, then (b) with hashicorp/raft.

- **M1, warm standby.** Documented Litestream sidecar (or built-in snapshot shipping), a
  `promote` procedure that fences the old primary, copies CA files once and invalidates
  pre-promote tokens. The hub endpoint list in `EnrollResponse`/`Welcome` lands here, so agents
  already fail over to a promoted standby.
- **M2, Raft spike.** FSM around typed store commands, mTLS raft transport using hub certs, 3-node
  compose e2e: kill the leader, and agents reconnect and devices stay visible. Measure failover time
  and hub RSS.
- **M3, Raft production.** Leader-only sweeper with grace period, SSE from apply, membership CLI
  (add or remove peer), rolling-upgrade and migration rules, the chosen CA strategy.

**Open decisions for the maintainer**

1. CA strategy: replicate the key, per-hub intermediates, or leader-only signing.
2. Warm standby mechanism: Litestream sidecar, or built-in pure-Go snapshot and WAL shipping.
3. Agent streams: leader only (followers redirect), or any node with writes forwarded.
4. Presence writes: every heartbeat through Raft, or only online/offline transitions.
5. UI failover: require a shared DNS name/VIP, or accept re-login on another hub.
6. Raft log store: raft-boltdb, or a log table in SQLite.
7. Cluster sizes: 3 and 5 voters only, or also non-voting read replicas.

Resolved on 2026-11-17, except item 2: 1 → HA-D2, 3 → HA-D3, 4 → HA-D5, 5 → HA-D7, 6 → HA-D4,
7 → HA-D6. Item 2 was not decided; HA-D1 goes straight to Raft.

## Decisions (2026-11-17)

- **HA-D1. Full Raft cluster** with hashicorp/raft. A single hub stays the default and behaves
  exactly as today, as a cluster of one, with no new flags needed.
- **HA-D2. The CA key is replicated to every voter**, each keeping it at 0600. CLAUDE.md's rule
  "the hub CA key never leaves the hub data dir" becomes "never leaves a hub voter's data dir"
  (CLAUDE.md updated in HA-2).
- **HA-D3. Agents stream to the leader only**; followers refuse and name the leader.
- **HA-D4. Raft log store is raft-boltdb** (bbolt, pure Go). The FSM applies typed commands to the
  local SQLite file.
- **HA-D5. Presence:** only online/offline transitions and boot_time changes go through Raft;
  last_seen is batched about every 30 s.
- **HA-D6. 3 or 5 voters only**; no non-voting replicas yet.
- **HA-D7. UI failover: sessions are replicated.** A shared DNS name keeps the login; a different
  hostname means a new login (cookies are per host).
- **HA-D8. Hub-to-hub traffic is Raft over mTLS using the hub CA.** Nodes join with
  `hearth hub --join <peer>` plus a cluster join token.

### HA-1: store commands (the FSM seam)

Every write in `internal/store` goes through `Applier.Apply(ctx, Command) (Result, error)`. A
`Command` is a typed value (`UpsertDevice`, `ReportFacts`, `MarkSeen`, `SetBootTime`,
`MarkOffline`, `CreateToken`, `ConsumeToken`, `CreateCert`, `RevokeDevice`, `AppendAudit`,
`SetPasswordHash`, `CreateSession`, `DeleteSession`) that carries every non-deterministic input:
timestamps as unix milliseconds, secret hashes, and JSON documents as strings stored byte for byte.
The default applier is `Store.ApplyLocal` (one local transaction); `store.WithApplier` lets the
Raft layer wrap it without touching callers. Reads stay direct SQL.

- Encoding: versioned JSON envelope `{"v":1,"op":"mark_seen","cmd":{...}}` via `EncodeCommand` /
  `DecodeCommand`. Chosen over protobuf because the commands are internal to the hub, small and
  low-rate (consensus cost dwarfs encoding), readable when debugging a Raft log, and need no
  generated code. Decoding rejects unknown versions, ops and fields, so a node never silently drops
  part of a write the others applied.
- `ConsumeToken` decides used/expired/unknown inside apply, in the same transaction as the
  `UPDATE`, so exactly one consume wins however often the log is replayed.
- `AppendAudit` gets its ID from AUTOINCREMENT in apply order; a zero timestamp is filled in when
  the command is built, never during apply.
- `Store.Snapshot` writes a `VACUUM INTO` copy (in a 0700 temp dir next to the database) to the
  writer; `Store.Restore` stages the incoming copy, checks it (`quick_check` plus a goose version)
  and copies it into the live database in one transaction with SQLite's backup API, so the open
  `*sql.DB` stays valid.

### HA-2: Raft node, join flow and replicated CA

`internal/cluster` wraps hashicorp/raft. Raft state lives in `<data-dir>/raft/`: `raft.db` (bbolt log
and stable store), `snapshots/`, `node-id`, the hub node certificate `node.crt`/`node.key` (0600) and,
on a joined hub, `join-url`.

- **Standalone stays standalone.** A hub with no cluster flags and no `raft/` dir runs the old code
  path untouched: no Raft, no extra port, no control socket. Raft starts only with `--cluster` (form a
  cluster from this hub), `--join`, or once `raft/` exists. This is simpler and safer than running every
  hub as a one-node cluster, which would add a listener, a second fsync per write and make CLI writes
  depend on a running hub for users who never cluster.
- **State machine.** Each committed entry is decoded with `store.DecodeCommand` and applied with
  `Store.ApplyLocal`, the leader included, so every node applies the same bytes. Domain errors
  (`store.IsDomainError`: not found, token used or expired, constraint violations) go back to the
  proposer. Any other error halts the state machine (no further applies or snapshots) and calls
  `Config.OnFatal`, which stops the hub; on restart raft restores the latest snapshot and replays the log.
- **Snapshots.** `FSM.Snapshot` copies the database with `VACUUM INTO` while raft holds applies back, so
  the copy matches its index; `Persist` streams it. Restore checks the schema version.
- **Forming a cluster from existing data.** The first clustered start writes a raft snapshot of the
  current database as index 1 with a one-voter configuration (as `raft.RecoverCluster` does) instead of
  `BootstrapCluster`. Logs then start at index 2, so every joiner is sent a snapshot first and never
  misses pre-cluster state.
- **Transport.** TCP with mutual TLS 1.3. Both ends present a hub node certificate from the hub CA with
  URI SAN `urn:hearth:hub:<node-id>` (server and client auth); device certificates are refused. Peers
  are verified against the CA, not by host name. A voter renews its own node certificate with the CA key
  30 days before expiry.
- **Applier.** `*cluster.Node` is the store's `Applier`. On the leader it proposes and waits; on a
  follower it returns `*cluster.ErrNotLeader{LeaderID, LeaderAddr}` without proposing. `OnLeaderChange`
  and `WaitReady` are the hooks for HA-3 (leader-only sweeper, follower redirects, forwarding).
- **Join.** `hearth cluster token create` (policy `cluster.token.create`, dangerous) stores a hashed,
  single-use `hearthj1.<secret>.<ca-fingerprint>` token through Raft (`CreateJoinToken`, table
  `join_tokens`, separate from enrollment tokens). `hearth hub --join https://<member>:7443` with
  `HEARTH_JOIN_TOKEN` pins the CA by fingerprint and calls `ClusterService.Join`
  (`proto/hearth/cluster/v1`) on the member's TLS listener. A follower answers `FAILED_PRECONDITION` with
  the leader in the error metadata and the client retries on the leader's host with the same port. The
  leader (policy `cluster.join`, dangerous, actor `join_token`) checks the schema version and the node
  ID first, then signs the CSR, consumes the token and adds the hub as a **non-voter**, so a hub that
  never comes up cannot stall quorum. The response carries the node certificate, the CA certificate and
  the CA key; the new hub writes `ca.key` at 0600 and never logs it. Once running, the hub calls
  `ClusterService.Promote` with its node certificate (policy `cluster.promote`, dangerous, actor `hub`)
  and the leader makes it a voter.
- **Schema guard.** A member opens its store with `store.WithoutUpgrade()`: a new database is
  initialized, an existing one must already be at the binary's schema. Join refuses a binary whose schema
  differs from the cluster's, and restore refuses a snapshot of another schema. Rolling migrations: #25.
- **Local CLI.** A member serves a control socket (`<data-dir>/hearth.sock`, or a private 0700 dir under
  the temp dir when that path is too long for a unix socket): `GET /v1/status` for
  `hearth cluster status`, and `POST /v1/apply` so CLI writes (`token create`, `device revoke`,
  `admin set-password`, `cluster token create`) go through Raft instead of the local file. On a follower
  HA-3 forwards them to the leader.

### HA-4: agent failover and leader redirect

- `hub.Config.Leadership` (`IsLeader`, `LeaderAgentURL`, `AgentURLs`) is the hub's view of the
  cluster. Nil means a single hub: always the leader, and Welcome lists no hubs, so agents keep only their
  join URL, exactly as before.
  HA-3 implements it over the Raft node.
- A follower refuses `AgentService.Connect` (before any registry write) and `EnrollService.Enroll`
  with `FAILED_PRECONDITION` plus a `hearth.agent.v1.NotLeader { leader_url, hubs }` detail.
  FailedPrecondition rather than Unavailable: retrying the same hub cannot succeed until leadership
  changes, so generic retry logic must not treat it as transient; the detail says where to go.
  `leader_url` is empty while no leader is known.
- `Welcome.hubs` lists every hub's agent URL. The agent keeps them in `hubs` in its data dir (one
  URL per line, 0600, replaced atomically); `hub_url` stays the URL given to join and is always
  kept in the list. The list is rewritten when a Welcome changes it, with the welcoming hub first.
- Reconnects: a failed attempt moves straight on to the next hub; only after every hub failed in a
  row does the agent back off (the existing exponential backoff, and the quick retry of the same
  hub after a session of at least 1 s). A NotLeader refusal jumps to the named leader at once, but
  still counts as an attempt of the round, so followers naming each other cannot cause a hot loop.
- `hearth agent join` through a follower retries once at the leader it names and saves the hubs.

### HA-3: leader-only services, write forwarding and presence batching

Operator view: [../cluster.md](../cluster.md).

- **Agent URLs.** Raft knows only hub-to-hub addresses, so each hub records its own agent-facing URL
  (`https://<first --host>:<TLS port>`) as a replicated `SetHubURL` command (table `cluster_hubs`,
  migration 00005) once it has caught up after a start, and again whenever it changes.
  `*cluster.Node` is the hub's `Leadership`: `LeaderAgentURL` and `AgentURLs` read the Raft
  configuration plus that table. A member that has not recorded a URL yet falls back to
  `https://<its raft host>:<this hub's TLS port>` (the HA-2 join redirect rule). Recording the URL was
  chosen over deriving it from `--advertise`: Raft may run on another name or network than the one
  agents use, hubs on one host need different ports, and the URL must match the hub's TLS
  certificate, which the first `--host` does.
- **Write forwarding.** A hub binds its store with `Node.BindForwarding`: on the leader a write is
  proposed as before; on a follower `ApplyOrForward` sends the encoded command to the leader's
  `ClusterService.Forward` on its TLS listener. The caller authenticates with its hub node certificate
  (`urn:hearth:hub:<id>`) and must be in the Raft configuration; device certificates, missing
  certificates and non-members are refused, and only the leader serves it (a follower answers
  FAILED_PRECONDITION, like Join). The follower retries only when the command was certainly not
  applied: the target was not the leader, or could not be dialed. While no leader is known or
  reachable it retries for 5 s, then fails with `store.ErrUnavailable` (API: 503
  `cluster_unavailable`). Timeouts and lost leadership after proposing are returned, never retried,
  since the entry may still commit. The control socket's `/v1/apply` uses the same path, so CLI writes
  work on followers.
- **Policy and audit with forwarding.** The decision is made and audited where the user's request
  arrived, as on a single hub: `policy.Do` runs on that hub, and both the action's writes and its
  `AppendAudit` go through `ApplyOrForward`. `Forward` itself makes no decision and writes no audit
  entry: it is replication, authenticated as a hub, not as a user. When an action and its audit
  append fail for the same root cause (no leader), `policy.Do` now reports the cause once.
- **Leader-only presence.** `Registry.RunReplicated` follows `OnLeaderChange`. When the node leads
  and `WaitReady` (the barrier) has returned, a **term** starts: agent streams are accepted only within
  a term (a leader still catching up answers Unavailable), and the sweeper and the last_seen flusher
  run. When leadership ends, the term is cancelled: every open agent stream ends with
  FailedPrecondition and the `NotLeader` detail (HA-4 moves the agent), then the pending last_seen
  batch is written, through the new leader if there is one. Followers never sweep, so they never log
  ErrNotLeader.
- **Presence on a new leader.** The old leader's in-memory last_seen (up to one flush) dies with it,
  so stored last_seen can be older than `OfflineAfter`. A new leader therefore treats every online
  device as seen at the moment its term started: a device goes offline only after a full
  `OfflineAfter` without a heartbeat under the new leader. Agents that reconnect in time keep their
  status; their Hello stores fresh facts and last_seen and publishes `device.updated`, not
  `device.online`. No device flaps offline and back.
- **HA-D5 batching (clustered only).** Facts, online transitions (`MarkSeen` for a device that is not
  online) and boot_time changes go through Raft at once. A heartbeat from an online device only
  updates the leader's memory; `MarkSeenBatch` writes all pending ones every 30 s, in ID order, moving
  last_seen only forward and never touching a status, so replay is deterministic. The leader's sweep
  compares the newest of stored last_seen, memory and the term start against `OfflineAfter`, and
  marks the silent devices offline by name (`MarkDevicesOffline`) after flushing their pending
  last_seen. The API overlays the leader's in-memory last_seen on device reads, and events carry it.
  Standalone hubs keep writing every heartbeat (`MarkSeen`, and `MarkOffline` with a cutoff): a single
  node gains nothing from batching, and its behaviour stays exactly as before.
- **Reads after a restart.** The blocking `WaitReady` at start is gone. Until it returns, the JSON API
  (not the static UI) holds each request for up to 5 s and then answers 503 `catching_up`.
  `HEARTH_ADMIN_PASSWORD` is applied only after catching up, so a new member never replaces the
  cluster's password because its own copy is still empty.
- **Not in HA-3.** Live SSE events on followers (added later, see "SSE on followers" below; #27),
  member removal, and rolling schema upgrades (#25).

### HA-5: cluster failover end to end

`test/e2e/cluster_test.go` (`TestClusterFailover`, `task e2e:cluster`, CI job "E2E cluster") guards
hub failover the way `TestHeadlineDemo` guards the headline demo. It runs three hubs and one agent
from `test/e2e/cluster.compose.yaml` and finds the leader with `hearth cluster status --json` on each
hub (`docker compose exec`), never by assuming hub-a. Every bound is a named constant, and none may
be raised to make CI pass:

| Scenario | Bound |
| -------- | ----- |
| hub-a forms the cluster (`--cluster`); hub-b and hub-c join with `HEARTH_JOIN_TOKEN`; all report one leader and 3 voters | `FormationWithin` 60 s |
| An agent joins through a follower (sent on to the leader) and is online | `DeviceVisibleWithin` 10 s, the headline constant |
| The leader is killed (SIGKILL); a survivor is elected and the agent is connected to it (its `last_seen` on the new leader is after the kill) | `FailoverWithin` 10 s |
| The device stays `online` on the new leader, polled every 200 ms, until `OfflineWithin` (40 s) after the election, past one full offline timeout of the new term; no hub logs `device.offline` | `OfflineWithin` |
| On the remaining follower: an API login and token creation, and `hearth token create` on its host | (fails the test on error) |
| That follower is stopped: the leader, alone, answers an API write with 503 `cluster_unavailable` | `UnavailableWithin` 15 s |
| It starts again: API writes succeed again | `WritesResumeWithin` 15 s |
| The killed hub starts again: it is a follower, has applied the leader's commit index, and its API (after any `catching_up` answers) lists the device, online, with its original ID | `RejoinWithin` 20 s |
| Since the quorum came back, the agent is connected to the leader again. While no hub took it, it backed off exponentially (capped at 1 min), so this bound is the cap plus `FailoverWithin` | `AgentBackWithin` 70 s |
| The leader is killed for good and a survivor is elected; `hearth cluster remove` on the remaining follower (forwarded to the leader) leaves both survivors reporting 2 voters (#29) | `FailoverWithin`, then `RemoveWithin` 10 s |
| hub-d joins in its place with a new join token: one leader and 3 voters again | `ReplaceWithin` 30 s |
| The leader is killed once more: the other two elect a leader, an API login and token creation work on it, and the agent is connected to it | `FailoverWithin` 10 s |

Local runs (Colima, arm64) took: formation 6.2–11.4 s, enroll to online 0.3–1.0 s, kill to election
2.0–3.8 s, kill to agent on the new leader 2.4–6.1 s, no-quorum write to 503 5.6–11.0 s (the action
and its audit append may each wait 5 s for a leader), writes resuming 0.9–1.8 s, the killed hub
serving the device 1.4–2.8 s, and the agent back after the quorum loss 3.4–6.9 s. A run takes about
60–85 s plus the image build, most of it the 40 s offline watch. The replacement steps (#29) took:
removal to 2 voters 0.24–0.26 s, hub-d joined to 3 voters 2.6 s, and after the next leader kill an
election in 2.4 s and login, token and agent on the new leader in 3.3 s.

- **Fix found by the test: certificate checks on a lagging hub.** An agent reconnecting after the
  quorum came back was answered `Unauthenticated: certificate unknown` by a follower that had just
  restarted and was still replaying its log (its store did not know the device's certificate yet).
  Agent certificates are checked against the hub's local store, which only a leader within a term
  (after the barrier) can vouch for. Now a certificate that is unknown or revoked locally is rejected
  with Unauthenticated only there; a follower answers NotLeader (naming the leader) and a leader still
  taking over answers Unavailable (`Registry.certAuthority`, tests `TestCertAuthority` and
  `TestOnlyTheLeaderRejectsAgentCerts`). The agent was never at risk of bricking itself: it treats
  every failed attempt alike and keeps retrying, so the impact was a lost redirect and a longer
  backoff, not a lost device.
- **Agent backoff after a quorum loss.** While no hub takes it, the agent fails whole rounds of hubs
  and backs off exponentially up to its 1 min cap. After a long outage it can therefore take up to
  that cap to come back once the quorum returns, hence `AgentBackWithin`. The device does not go
  offline meanwhile unless the wait exceeds the offline timeout of the new term.

Not covered: live SSE on followers (#27), rolling schema upgrades (#25). Revocation of a removed
hub's certificate is covered by unit tests in `internal/cluster/members_test.go`, not end to end.

### SSE on followers (#27)

A UI open on a follower gets the same live device events as one on the leader. Events are published
from the FSM apply, as section 3 ("SSE clients and sessions") proposed, but the leader keeps
publishing from its own calls, so its behaviour, and a standalone hub's, is unchanged.

- **Hook.** `Node.ObserveApplies(o cluster.ApplyObserver)` registers an observer with
  `Applied(cmd store.Command, res store.Result, local bool)` and `Restored()`. The FSM calls `Applied`
  after each successful apply (domain errors are not reported), on raft's apply goroutine, in log
  order. `local` is true when this node proposed the entry: it is the leader of the entry's Raft term
  when it applies it (only that term's leader appends its entries). A leader that steps down before
  applying its own entry answers false, and its proposer got `ErrLeadershipLost` and published
  nothing, so the entry is still published exactly once. `*hub.Registry` is the observer; the hub
  registers it after the node starts, before it serves the API. It is a method rather than a
  `Config` field because the registry needs the store, which is opened with the node's applier.
- **Mapping** (`Registry.Applied`, for entries that are not local): `ReportFacts` and `MarkSeen` give
  `device.online` if the device was not online and `device.updated` otherwise; `SetBootTime` gives
  `device.updated`; `MarkOffline` and `MarkDevicesOffline` give `device.offline` per changed device;
  `MarkSeenBatch` gives `device.updated` for each device whose last_seen it moved (the only case that
  reads rows from the local store). `UpsertDevice` (enrollment), `RevokeDevice` and every other
  command publish nothing, as on the leader. The payload is the stored row, the same JSON as an
  `/api/v1/devices` item on that hub. Followers do not log these transitions; the leader logs those
  it made. A leader's Heartbeat that brings a device online and changes its boot time publishes one
  `device.online`; a follower publishes `device.online` then `device.updated` for the two entries.
  The final state is the same.
- **No duplicates, clean term changes.** On the leader every local entry is skipped, so nothing is
  published twice. The source follows the log rather than a flag the registry flips: a new leader
  publishes the tail of the previous term from the log while it catches up, then its own calls; an
  old leader publishes from the log from the first entry of the next term. Known edge: a presence
  write the old leader starts in the instant between losing leadership and ending its term (a sweep
  or an online transition) is forwarded to the new leader and can be published twice on the old
  leader, as the same event. The UI applies events idempotently, so that is harmless.
- **Backpressure.** Publishing never blocks: the bus drops a subscriber whose 64-event buffer is full
  (its SSE stream ends, EventSource reconnects and the UI refetches). The observer takes no registry
  lock (the leader holds it while it waits for its own writes) and skips all work when nobody is
  subscribed, so slow SSE clients cannot stall Raft.
- **Snapshot restore.** A restore (a far-behind follower installing the leader's snapshot) makes no
  `Applied` calls; `Restored` ends every subscription instead, so clients resync with a list call.
  At start nobody is subscribed until the hub has caught up (the API waits for it), so the restored
  snapshot and the replayed log publish nothing.
- **last_seen lag.** A follower's last_seen trails the leader's by up to one batch (30 s, HA-D5):
  the leader overlays its in-memory value, a follower only has the stored one. This is accepted. The
  UI shows "now" for an online device and derives the online state from `status`, never from the age
  of last_seen, so a follower does not show a device as stale.
- **Tests.** `internal/hub/applied_test.go` (the mapping, local entries, standalone, restore);
  `internal/cluster/events_test.go` on an in-process 3-hub cluster: `TestFollowerSSE` (online, updated
  and offline over HTTPS SSE on a follower, in order, within bounds, payload equal to the list item,
  exactly once on the leader), `TestSlowSubscriberDoesNotBlockApplies` and
  `TestLeadershipChangeMidStream`.
