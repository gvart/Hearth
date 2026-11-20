# Implementation: leaderless AP cluster (temporary)

Tracking doc for [#251](https://github.com/gvart/hearth/issues/251). Design and decisions:
[docs/design/ap-cluster.md](../design/ap-cluster.md). Tick items as their PR merges. **Delete this file
in the PR that completes item 8.**

## Decisions (owner, 2026-11-20)

- Replace Raft entirely: one replication model.
- Combinable roles `{node, storage, master}`, device opt-in via `--allow-roles`.
- Sharded, consistent hash, `N` replicas per key; a single host may run `N=1` with a "not HA" warning.
- Last-writer-wins by HLC; append-only audit; deny-wins revocations.
- Writes: `W=min(2,N)` for critical tables, `W=1` otherwise; `R=1` + read repair + anti-entropy.
- Membership: hashicorp/memberlist over mTLS TCP.
- Master-owned tokens and approvals; automations owned via the master hash ring.
- Config (policy, notify, automations, runbooks) replicated as store documents.
- An isolated master (60 s with no peers) fails closed for dangerous actions.
- No migration from Raft clusters (pre-1.0).

## Work items

Parallel: 2 ∥ 3, then 4 ∥ 5. Everything else is sequential.

- [x] **1. Design note.** `docs/design/ap-cluster.md`.
  verify: owner approves the PR. depends on: none.
- [ ] **2. Roles + membership.** Role set and `--allow-roles` in config; memberlist with an mTLS TCP
  transport (on `--gossip-listen :7445` while Raft keeps 7444; one port from item 8); member metadata (roles, schema, HLC, digest); `hearth cluster status` lists
  members and roles. Raft still runs alongside, untouched.
  verify: unit tests for join/leave/fail detection and for refusing a cert from a non-member; a role
  outside `--allow-roles` is refused. depends on: 1.
- [ ] **3. Versioned store.** HLC package with 60 s skew bound; `_hlc/_origin/_deleted` columns
  (migration); commands emit row mutations; `ApplyLocal` merges LWW; append-only audit with global
  ids; deny-wins revocations; natural-key ids for unique tables; tombstone GC.
  verify: property test where shuffled mutation orders converge to identical DBs; negative tests:
  revocation is never cleared, audit is never overwritten, a future-skewed HLC is rejected.
  depends on: 1.
- [ ] **4. Sharding + replication.** Hash ring over storage members; partition keys; W/R levels;
  hinted handoff; read repair; Merkle anti-entropy; scatter-gather list queries.
  verify: 3 storage members, `N=2`: kill one, nothing is lost for critical writes; a split and heal
  converges; benchmark the devices list and audit page against single-hub numbers.
  depends on: 2, 3.
- [x] **5. Config documents.** Policy, notify (sealed), automations and runbooks as global documents;
  `hearth config import|export`; first-start import of existing files; remove the drift warning
  except for host flags.
  verify: an edit on one master is applied on another; a policy import is audited and denied without
  permission. depends on: 3.
- [ ] **6. Multi-master.** Agents stream to any master with endpoint list failover; `device → master`
  routing and API forwarding; presence ownership; automation and runbook ring; master-owned tokens
  and approvals carrying the owner URL; CA key on masters only; isolation fail-closed; update the
  CLAUDE.md CA rule.
  verify: kill any master and the agent is back in < 10 s; a token cannot be used twice across
  masters during a split; an isolated master denies dangerous actions after 60 s.
  depends on: 4, 5.
- [ ] **7. Promote / demote.** `cluster.promote|demote|remove` policy actions (dangerous, audited)
  in CLI, API and UI; shard hand-off before storage demotion; master demotion revokes tokens and
  closes approvals.
  verify: negative tests (no opt-in, policy denied, last master, below `N=1`); a UI check with
  Playwright. depends on: 6.
- [ ] **8. Remove Raft.** Delete the Raft code in `internal/cluster`, the bbolt dep and the 7444 Raft
  usage; rewrite `docs/cluster.md`; mark `ha-hub.md` superseded; replace `e2e:cluster` with an AP
  test (kill a master, kill a storage member, split and heal); update CLAUDE.md layout and commands.
  verify: `task test lint e2e e2e:cluster` all green. Delete this file. depends on: 7.

## Open risks

- Rewriting about 50 command `apply`s (item 3) is the largest diff; split it per table group if needed.
- Scatter-gather latency on Pis (item 4 benchmark gates item 8).
- The agent `node` role must stay under 25 MB: no memberlist at idle.
