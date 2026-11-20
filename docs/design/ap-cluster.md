# Leaderless AP cluster: node, storage and master roles

**Status:** proposal, decisions taken with the owner on 2026-11-20. Tracking: [#251](https://github.com/gvart/hearth/issues/251).
**Supersedes:** [ha-hub.md](ha-hub.md) (the Raft cluster). Its non-goal "surviving a network
partition with writes on both sides" becomes the goal.

## 1. Goal

No single leader. Any host can take one or more roles; the control plane stays writable on every
side of a network split and converges when the split heals (AP in CAP terms). The admin promotes and
demotes roles. A single host still works out of the box.

**Non-goals:** BFT or untrusted members (same reasoning as ha-hub.md §1), CRDT data types,
tunable per-request R/W, a live upgrade from a Raft cluster (pre-1.0: rebuild from a backup).

## 2. Roles

A host has a **set** of roles; any combination is valid.

| Role | Runs | Typical host | Budget |
|---|---|---|---|
| `node` | the agent: facts, heartbeat, exec | MCU, TV, old phone, everything | 25 MB idle RSS (unchanged) |
| `storage` | a shard replica of the store (SQLite) | Pi 4/5, NAS, server | not bound by the agent budget |
| `master` | API, UI, MCP, agent streams, automations, runbooks, enrollment, CA | Pi 5, server | not bound by the agent budget |

- **Default:** a fresh `hearth hub` is `{master, storage}` with replication factor `N=1`, and
  `hearth agent` is `{node}`. The UI and `hearth cluster status` show "not highly available" while
  fewer than 2 storage members or fewer than 2 masters exist. The < 10 s demo is unchanged.
- **Device opt-in (capability ceiling).** A host's local config lists the roles it *allows*
  (`--allow-roles storage,master`, env `HEARTH_ALLOW_ROLES`). The hub can grant only roles in that
  list; nothing turns a TV into a storage member remotely.
- **Promote and demote** are admin actions in the UI, CLI (`hearth cluster promote|demote <host>
  <role>`) and API, class `dangerous`, through `internal/policy`, audited.

## 3. Membership

- **Gossip:** hashicorp/memberlist (SWIM) among storage and master members; `node`-only hosts do
  not gossip. Each member's metadata carries: roles, allowed roles, schema version, HLC, config
  digest.
- **Transport:** a custom memberlist transport over TCP with mutual TLS using hub-CA member
  certificates (the current hub node certificate, URI SAN `urn:hearth:member:<id>`), so the
  "mTLS everywhere" rule holds. No UDP, no shared gossip key. One port, `7444` (was Raft), carries
  gossip and replication.
- **Join:** unchanged shape: `hearth hub --join <any-master>` plus a single-use join token from that
  master (master-owned, §6). The joiner gets a member cert and, if it is allowed `master`, the CA key.
- **Removal:** `hearth cluster remove <id>` revokes the member's certs (deny-wins, §5.4) and
  re-replicates its shards.

## 4. Data model

### 4.1 Versioned rows

Storage keeps the current SQLite schema, plus three columns on every replicated table:
`_hlc` (hybrid logical clock, 64-bit), `_origin` (member id that stamped it), `_deleted` (tombstone).
A write is a **row mutation** `(table, pk, columns, hlc, origin, deleted)`. Merge rule:
**last-writer-wins** on `(hlc, origin)`, applied per row. The existing typed `store.Command`s stay as
the write seam: each `apply` is rewritten to emit row mutations instead of running SQL directly, and
`ApplyLocal` merges mutations. Reads stay plain SQL on the local file and ignore tombstones.

### 4.2 HLC and clock skew

Only masters and storage members stamp (agent writes are stamped by the master that receives them).
A member rejects, and alerts on, any remote timestamp more than **60 s** ahead of its own
physical clock, so a Pi with a wrong RTC cannot win every conflict forever. A member whose clock is
behind still advances via the HLC's logical part. A member refuses to take the `master` or
`storage` role until its clock is within the bound of a majority of reachable members.

### 4.3 Tombstones

Kept for a GC window (default **7 days**). A storage member that has been unreachable for longer
than the window must rejoin **empty** and resync, so it cannot resurrect deleted rows. Enforced from
the member's last-seen in gossip.

### 4.4 Rows that LWW must not merge

| Kind | Tables | Rule |
|---|---|---|
| **Append-only** | `audit_log` | Insert-only, never updated or tombstoned. The `AUTOINCREMENT` id becomes a globally unique id `(hlc, origin, seq)`; listing merges by HLC. The append-only triggers stay. |
| **Deny-wins** | revocations in `certs`, `hub_certs`, `mcp_tokens`, `dashboard_tokens`, `panel_links`, device revoke | `revoked_at` is set-once: once a replica has it, no later write clears it (two-phase set). |
| **Master-owned** | `tokens`, `join_tokens`, `approvals`, `approval_links`, `ca_rotations` | Created, consumed and decided only on the owning master (§6). Other replicas hold a read-only copy. |

### 4.5 Uniqueness and foreign keys

A shard cannot enforce a `UNIQUE` across shards or an FK across shards.

- **Natural-key ids:** `kube_clusters`, `proxmox_servers` (UNIQUE name) and `panel_links` get ids
  derived from the unique key (hash of the name), so two masters creating "the same" row converge to
  one row by LWW instead of violating a constraint.
- **Secret-derived uniques** (`mcp_tokens`, `dashboard_tokens` hash, `audit_key`): collisions are
  impossible by construction; the constraint stays local only.
- **FKs** (`certs → devices`, `panel_links → panels`) become soft references: the row is co-located
  with its parent by sharding on the parent key (§5.1), and a dangling reference reads as "not found".

## 5. Sharding and replication

### 5.1 Placement

Consistent-hash ring over **storage** members (virtual nodes), replication factor `N`
(`--replicas`, default `min(2, storage members)`, never below 1). The shard key is the row's
**partition key**: the device id for `devices`, `certs`, `telemetry`, `network_hosts` scanned by it;
the panel id for `panels` and `panel_links`; otherwise the table's primary key. Small, global tables
(`admin`, policy and config documents, §7) use `N = all storage members`.

### 5.2 Writes and reads

- **Write levels:** *critical* writes (audit, certs, revocations, tokens, approvals, sessions,
  config documents) wait for `W = min(2, N)` replicas and fail fast with `cluster_unavailable` if
  fewer are reachable. Every other write (presence, facts, metrics, scans, run history) waits for
  `W = 1`. Copying to the remaining replicas is asynchronous.
- **Reads:** `R = 1` from the nearest live replica, with **read repair** on any version difference
  seen, plus periodic **anti-entropy** (Merkle tree per shard range) between replicas.
- **Hinted handoff:** a write meant for an unreachable replica is kept as a hint on the coordinator
  and delivered when it returns.

### 5.3 Queries that become scatter-gather

Every list query that is not keyed by one partition fans out to all shards and merges on the
master. The cost is visible here so the choice to shard is made with it:

| Query | Today | AP |
|---|---|---|
| devices list, UI home, `hearth devices` | one SELECT | one per storage member, merged by name |
| audit log page / fold | indexed page | k-way merge by HLC across members, cursor = HLC |
| network hosts, topology | one SELECT | fan-out |
| automation runs, runbook runs, approvals list | one SELECT | fan-out, merged by time |
| telemetry, panels list | one SELECT | fan-out |

A master caches nothing across requests; pagination cursors become HLC values.

### 5.4 Revocation propagation

Revocations are written critical (`W=2`) **and** broadcast on gossip at once, so every reachable
master learns within a gossip round. **Isolation bound:** a master that has not reached any other
member for **60 s** refuses `dangerous` actions and new enrollments (fails closed); reads and `safe`
actions keep working. This bounds how long a revoked credential can still be used on the cut-off
side.

## 6. Masters

- **Agent streams:** an agent dials any master from the list it received at enroll and in every
  `Welcome`, and fails over through the list with the existing backoff. Each master records
  `device → master` as a soft-state row (LWW, W=1). An API call on master B for a device streaming
  to A is **forwarded** to A over the member mTLS channel; if A is gone, the agent is already
  reconnecting elsewhere.
- **Presence:** the master holding a device's stream owns its online/offline; devices with no stream
  are swept by the master that owns the device id on the master ring, after one offline grace period.
- **Automations and runbooks:** each is owned by one master on a consistent-hash ring over masters
  and moves on failure. During a split both sides can run it: accepted (AP).
- **Master-owned operations:** an enrollment or join token, an approval and an approval link are
  owned by the master that created it; only it consumes or decides them, with its local atomic
  update, so "single use" holds without a quorum. The token embeds its owner's URL, so the install
  one-liner reaches the owner directly (demo bound unchanged). If the owner is down, the token cannot
  be used until it returns; the admin creates a new one elsewhere.
- **CA key:** held by every master at 0600, sent only over the pinned mTLS join channel or the
  `FetchCAKey` channel during rotation, never stored in the store or in replication traffic. A CA
  rotation is master-owned by the master that starts it.
- **Demoting a master:** its unused tokens and join tokens are revoked; its open approvals are closed
  as `expired: master demoted`; it deletes its CA key; its agents are told to move on; its automations
  rehash. Demoting the last master is refused.
- **Demoting a storage member:** its shards are handed off to the next replicas first; the demotion
  completes only once every shard it held has `N` other copies. Demoting below `N=1` is refused.

## 7. Configuration as replicated documents

`policy.yaml`, `notify.yaml`, automations and runbooks become **documents in the store** (global
table, `N = all`, critical writes, LWW per document, every edit audited). Files on disk become
import/export: `hearth config import <dir>` and `hearth config export <dir>`; a fresh hub imports its
existing files once. This removes config drift and the drift warning. `notify.yaml` secrets are
sealed with the existing secret sealing before they enter the store. `--allow-dangerous-automation`
stays a per-host flag (a ceiling), so it is still compared and warned on.

## 8. Schema migrations

No log orders a `MigrateSchema` any more. Rules: migrations stay additive; every member gossips its
supported schema; a column or table is **written** only after every live member supports it; a
member too old for the cluster's oldest-written schema refuses to join. The goose version table stays
local.

## 9. Security rules that change

The CLAUDE.md rule on the CA key changes from "never leaves a hub voter's data dir … replicated only
over the pinned mTLS join channel" to **"never leaves a master's data dir"**, with the same
exceptions (encrypted admin backup, opted-in scheduled backup, `FetchCAKey` during rotation). The
update lands with the work item that moves the key (impl doc, item 6).

New action types, all `dangerous`: `cluster.promote`, `cluster.demote`, `cluster.remove`,
`config.import`. `config.export` is `read`.

## 10. Risks

- **Rewriting every `apply`** (about 50 commands) to emit row mutations is the bulk of the work; the
  store's existing tests are the safety net.
- **Scatter-gather latency** on a Pi with 3 storage members: measure the devices list and audit page
  against today's single query before ripping out Raft.
- **Anti-entropy cost** on SD cards: Merkle rebuild must be incremental.
- **Agent RSS:** the `node` role must not link memberlist or the replication code paths at idle;
  measure against the 25 MB budget.
