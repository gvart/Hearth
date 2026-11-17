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
