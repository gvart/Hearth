// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
)

// writesAt reports whether every member writes schema v: the store's
// database and its write schema are at v or newer.
func (s *Store) writesAt(ctx context.Context, v int64) (bool, error) {
	at, err := schemaVersion(ctx, s.db)
	if err != nil {
		return false, err
	}
	if s.writeSchema != nil {
		at = min(at, s.writeSchema())
	}
	return at >= v, nil
}

// auditChainPageCols are the columns of a page of sealed entries after the
// entry's position: its auditRawCols, its operation, and its outcome's
// auditRawArray (” if none), read raw so their seals can be checked.
const auditChainPageCols = auditRawCols + `, coalesce(audit_op, ''),
	coalesce((SELECT ` + auditRawArray + ` FROM audit_log o WHERE a.audit_op IS NOT NULL AND o.audit_outcome_of = a.audit_op
	          ORDER BY o._hlc DESC, o._origin DESC, o._seq DESC LIMIT 1), '')`

// auditChainFilter is the WHERE clause of a page, as in auditPageVersionSQL.
const auditChainFilter = `
	WHERE +audit_outcome_of IS NULL
	  AND (?1 = '' OR actor_kind = ?1)
	  AND (?2 = '' OR instr(actor_id, ?2) > 0)
	  AND (?3 = '[]' OR action IN (SELECT value FROM json_each(?3)))
	  AND (?4 = '[]' OR target IN (SELECT value FROM json_each(?4)))
	  AND (?5 = '' OR decision = ?5)
	  AND (?6 = 0 OR ts >= ?6)
	  AND (?7 = 0 OR ts < ?7)`

// auditPageShardChainSQL is auditPageShardSQL with the seals.
const auditPageShardChainSQL = `SELECT _hlc, _origin, _seq, ` + auditChainPageCols + `,
	       _hlc, _origin, _seq, _hlc, _origin
	FROM audit_log a` + auditChainFilter + `
	  AND (?8 = 0 OR (_hlc, _origin, _seq) < (?8, ?10, ?11))
	ORDER BY _hlc DESC, _origin DESC, _seq DESC LIMIT ?9`

// queryChain is queryShards once every member writes seals: each entry
// folded with its outcome on the member holding both, and their seals
// checked here.
func (r Audit) queryChain(ctx context.Context, f AuditFilter, actions, targets string, since, until int64, limit int) ([]AuditEntry, error) {
	sealedSince, err := r.s.auditSince(ctx)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	sealer := r.s.auditSealer()
	var before auditCursor
	if f.BeforeCursor != "" {
		if before, err = parseAuditCursor(f.BeforeCursor); err != nil {
			return nil, fmt.Errorf("list audit: %w", err)
		}
	}
	order := desc(then(byInt(0), byText(1), byInt(2)))
	rows, err := r.s.queryAll(ctx, gather{table: auditTable, order: order, limit: limit}, auditPageShardChainSQL,
		f.ActorKind, f.ActorID, actions, targets, f.Decision, since, until, before.hlc, limit, before.origin, before.seq)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var (
			e           AuditEntry
			c           auditCursor
			raw         auditRaw
			op, outcome string
		)
		if err := rows.Scan(&c.hlc, &c.origin, &c.seq, &raw.TS, &raw.ActorKind, &raw.ActorID, &raw.Action, &raw.Target,
			&raw.Decision, &raw.Result, &raw.Detail, &raw.Key, &raw.Origin, &raw.Seq, &raw.Prev, &raw.KID, &raw.MAC,
			&op, &outcome); err != nil {
			return nil, fmt.Errorf("list audit: %w", err)
		}
		e.ID, e.Cursor = c.hlc, c.String()
		e.TS, e.ActorKind, e.ActorID, e.Action, e.Target = fromMillis(raw.TS), raw.ActorKind, raw.ActorID, raw.Action, raw.Target
		e.Decision, e.Result, e.Detail = raw.Decision, raw.Result, json.RawMessage(raw.Detail)
		e.Verification = raw.verify(sealedSince, sealer)
		if raw.MAC != "" {
			e.SealOrigin, e.SealSeq = raw.Origin, raw.Seq
		}
		o, ok, err := rawOutcome(outcome)
		if err != nil {
			return nil, fmt.Errorf("list audit: %w", err)
		}
		if ok {
			e.Result, e.Detail = o.Result, json.RawMessage(o.Detail)
			e.Verification = worseVerification(e.Verification, o.verify(sealedSince, sealer))
		}
		if op != "" {
			e.Detail = withoutOpKeys(e.Detail)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditReport is what Verify found: the seals and the chains of the whole
// log.
type AuditReport struct {
	// CanVerify is false on a hub without the hub CA key: it checks no seal,
	// and its report says only what the sequence numbers show.
	CanVerify bool `json:"can_verify"`
	// Entries is how many entries the log holds, Legacy those without a
	// seal written before sealing started, and Unsealed those without one
	// written since: forged, or written by a member without the CA key.
	Entries  int `json:"entries"`
	Legacy   int `json:"legacy"`
	Unsealed int `json:"unsealed"`
	// Chains are the masters' chains, by origin.
	Chains []AuditChainReport `json:"chains"`
}

// OK reports whether the report found nothing wrong.
func (r AuditReport) OK() bool {
	if r.Unsealed > 0 {
		return false
	}
	for _, c := range r.Chains {
		if !c.OK() {
			return false
		}
	}
	return true
}

// AuditChainReport is what Verify found in one master's chain.
type AuditChainReport struct {
	Origin string `json:"origin"`
	// Last is the highest sequence number seen; Head, for this hub's own
	// chain, is the one it last appended (0 for another's): entries after
	// Last up to Head are missing.
	Last int64 `json:"last"`
	Head int64 `json:"head,omitempty"`
	// Verified counts the entries whose seal checks.
	Verified int `json:"verified"`
	// Unverified are the sequence numbers whose every copy has a seal that
	// does not check (or none can be checked here).
	Unverified []int64 `json:"unverified,omitempty"`
	// Missing are the sequence numbers no entry has: deleted entries.
	Missing []AuditRange `json:"missing,omitempty"`
	// Broken are the sequence numbers whose entry does not follow the one
	// before it: an entry moved, replaced or swapped.
	Broken []int64 `json:"broken,omitempty"`
	// Duplicates are the sequence numbers two different sealed entries
	// have: a master's chain taken up again from an older head (a database
	// restored from a backup).
	Duplicates []int64 `json:"duplicates,omitempty"`
}

// OK reports whether the chain has no gap, break or entry that does not
// verify.
func (c AuditChainReport) OK() bool {
	return len(c.Unverified) == 0 && len(c.Missing) == 0 && len(c.Broken) == 0 && len(c.Duplicates) == 0
}

// AuditRange is a range of sequence numbers, both ends included.
type AuditRange struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

// maxReported bounds each list of a chain report.
const maxReported = 100

// auditScanPage is how many sealed entries Verify reads at a time, per member.
const auditScanPage = 2000

// auditScanSQL selects a page of sealed entries in chain order after
// (?1, ?2).
const auditScanSQL = `SELECT ` + auditRawCols + ` FROM audit_log
	WHERE chain_origin IS NOT NULL AND (chain_origin > ?1 OR (chain_origin = ?1 AND chain_seq > ?2))
	ORDER BY chain_origin, chain_seq LIMIT ?3`

// Verify reads the whole log, every member's part of it, and checks every
// seal and every master's chain: sequence numbers missing, entries that do
// not follow the one before, seals that do not check. An entry is there if
// any replica answering holds a copy whose seal checks. Below schema 44 it
// reports every entry as legacy.
func (r Audit) Verify(ctx context.Context) (AuditReport, error) {
	sealer := r.s.auditSealer()
	rep := AuditReport{CanVerify: sealer != nil && sealer.CanVerify(), Chains: []AuditChainReport{}}
	ok, err := r.s.writesAt(ctx, auditChainSchema)
	if err != nil {
		return rep, fmt.Errorf("verify audit: %w", err)
	}
	if !ok {
		var n int
		if err := r.s.countAudit(ctx, &n); err != nil {
			return rep, fmt.Errorf("verify audit: %w", err)
		}
		rep.Entries, rep.Legacy = n, n
		return rep, nil
	}
	if err := r.countUnsealed(ctx, &rep); err != nil {
		return rep, fmt.Errorf("verify audit: %w", err)
	}
	var cur *chainScan
	flush := func() {
		if cur != nil {
			rep.Chains = append(rep.Chains, cur.report)
			rep.Entries += cur.entries
		}
	}
	origin, seq := "", int64(0)
	for {
		page, done, err := r.scanPage(ctx, origin, seq)
		if err != nil {
			return rep, fmt.Errorf("verify audit: %w", err)
		}
		for i := 0; i < len(page); {
			// The copies of one sequence number.
			j := i
			for j < len(page) && page[j].Origin == page[i].Origin && page[j].Seq == page[i].Seq {
				j++
			}
			if cur == nil || cur.report.Origin != page[i].Origin {
				flush()
				cur = &chainScan{report: AuditChainReport{Origin: page[i].Origin}}
			}
			cur.add(page[i:j], sealer, rep.CanVerify)
			origin, seq = page[i].Origin, page[i].Seq
			i = j
		}
		if done {
			break
		}
	}
	flush()
	// This hub's own chain: the entries after the last one seen, up to the
	// one it last appended, are missing.
	if head := r.ownHead(); head > 0 {
		i := slices.IndexFunc(rep.Chains, func(c AuditChainReport) bool { return c.Origin == r.s.origin })
		if i < 0 {
			rep.Chains = append(rep.Chains, AuditChainReport{Origin: r.s.origin})
			slices.SortFunc(rep.Chains, func(a, b AuditChainReport) int { return cmp.Compare(a.Origin, b.Origin) })
			i = slices.IndexFunc(rep.Chains, func(c AuditChainReport) bool { return c.Origin == r.s.origin })
		}
		c := &rep.Chains[i]
		c.Head = head
		if head > c.Last {
			c.Missing = appendRange(c.Missing, AuditRange{From: c.Last + 1, To: head})
		}
	}
	return rep, nil
}

// chainScan is Verify's state in one chain.
type chainScan struct {
	report  AuditChainReport
	entries int
	// prev are the MACs of the verified copies of the sequence number
	// before, prevSeq; nil if it had none.
	prev    []string
	prevSeq int64
}

// add takes the copies of one sequence number of the chain.
func (s *chainScan) add(copies []auditRaw, sealer AuditSealer, canVerify bool) {
	seq := copies[0].Seq
	s.entries++
	if seq > s.report.Last+1 {
		s.report.Missing = appendRange(s.report.Missing, AuditRange{From: s.report.Last + 1, To: seq - 1})
	}
	s.report.Last = seq
	// The link is checked when the entry before is there and verified.
	checkable := seq == 1 || (s.prevSeq == seq-1 && len(s.prev) > 0)
	var macs []string
	broken := false
	for _, c := range copies {
		if canVerify && c.verify(0, sealer) != AuditVerified {
			continue
		}
		if !slices.Contains(macs, c.MAC) {
			macs = append(macs, c.MAC)
		}
		follows := (seq == 1 && c.Prev == "") || (seq > 1 && slices.Contains(s.prev, c.Prev))
		broken = broken || (checkable && !follows)
	}
	switch {
	case len(macs) == 0:
		s.report.Unverified = appendCapped(s.report.Unverified, seq)
	default:
		s.report.Verified++
		if len(macs) > 1 {
			s.report.Duplicates = appendCapped(s.report.Duplicates, seq)
		}
		if broken {
			s.report.Broken = appendCapped(s.report.Broken, seq)
		}
	}
	if !canVerify {
		s.report.Verified = 0
	}
	s.prev, s.prevSeq = macs, seq
}

func appendCapped(s []int64, v int64) []int64 {
	if len(s) >= maxReported {
		return s
	}
	return append(s, v)
}

func appendRange(s []AuditRange, r AuditRange) []AuditRange {
	if len(s) >= maxReported {
		return s
	}
	return append(s, r)
}

// scanPage returns the next page of sealed entries after (origin, seq) in
// chain order, every copy of each, and whether it is the last. In a sharded
// cluster each member answers with a page of its own: the page ends where
// the shortest full one does, so no member's next entry is skipped.
func (r Audit) scanPage(ctx context.Context, origin string, seq int64) ([]auditRaw, bool, error) {
	var parts [][][]any
	if r.s.shards == nil {
		vals, err := r.s.readEvery(ctx, auditScanSQL, origin, seq, auditScanPage)
		if err != nil {
			return nil, false, err
		}
		parts = append(parts, vals)
	} else {
		wargs, err := wireArgs([]any{origin, seq, int64(auditScanPage)})
		if err != nil {
			return nil, false, err
		}
		rs, err := r.s.shards.ReadAll(ctx, auditScanSQL, wargs)
		if err != nil {
			return nil, false, err
		}
		for _, p := range rs {
			parts = append(parts, valuesRows(p.Vals))
		}
	}
	type pos struct {
		origin string
		seq    int64
	}
	var end *pos
	var page []auditRaw
	for _, p := range parts {
		for _, vals := range p {
			raw, err := scanRaw(vals)
			if err != nil {
				return nil, false, err
			}
			page = append(page, raw)
		}
		if len(p) == auditScanPage {
			last := page[len(page)-1]
			if end == nil || last.Origin < end.origin || last.Origin == end.origin && last.Seq < end.seq {
				end = &pos{last.Origin, last.Seq}
			}
		}
	}
	if end != nil {
		page = slices.DeleteFunc(page, func(e auditRaw) bool {
			return e.Origin > end.origin || e.Origin == end.origin && e.Seq > end.seq
		})
	}
	slices.SortStableFunc(page, func(a, b auditRaw) int {
		return cmp.Or(cmp.Compare(a.Origin, b.Origin), cmp.Compare(a.Seq, b.Seq))
	})
	return page, end == nil, nil
}

// countUnsealed counts the entries without a seal: legacy ones, older than
// when sealing started, and the others.
func (r Audit) countUnsealed(ctx context.Context, rep *AuditReport) error {
	since, err := r.s.auditSince(ctx)
	if err != nil {
		return err
	}
	rows, err := r.s.queryAll(ctx, gather{table: auditTable},
		`SELECT ts`+r.s.hidden(auditTable)+` FROM audit_log WHERE chain_mac IS NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ts int64
		if err := rows.Scan(&ts); err != nil {
			return err
		}
		rep.Entries++
		if ts < since {
			rep.Legacy++
		} else {
			rep.Unsealed++
		}
	}
	return rows.Err()
}

// ownHead is the sequence number of the last entry this member sealed since
// it started: 0 if none.
func (r Audit) ownHead() int64 {
	r.s.chain.mu.Lock()
	defer r.s.chain.mu.Unlock()
	return r.s.chain.seq
}

// countAudit counts the entries: on the local database, which holds every
// entry outside a sharded cluster; in one, on members that together hold
// them all.
func (s *Store) countAudit(ctx context.Context, n *int) error {
	if s.shards == nil {
		return s.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_log`).Scan(n)
	}
	rows, err := s.queryAll(ctx, gather{table: auditTable}, `SELECT 1`+s.hidden(auditTable)+` FROM audit_log`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		*n++
	}
	return rows.Err()
}
