// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
)

// Audit entry seals (#387).
//
// A master seals each audit entry it appends: the entry carries its place in
// the master's own chain (the master, a sequence number counting 1, 2, 3, ...,
// and the MAC of the master's entry before) and a MAC, by a key derived from
// the hub CA key, over that and every column of the entry. It is sealed on
// the master, before the entry is sent to the replicas that store it, so a
// storage-only member that applies or holds it cannot make a valid one, nor
// change one without the seal failing. A deleted entry is a missing
// sequence number of its master's chain; one moved or swapped breaks the
// chain's links. Masters check the seals when the log is read (Query) and
// scan whole chains for gaps (Verify).

// AuditSeal is an entry's place in its master's chain, and its MAC.
type AuditSeal struct {
	// Origin is the master that sealed the entry.
	Origin string `json:"origin"`
	// Seq is the entry's place in Origin's chain, from 1.
	Seq int64 `json:"seq"`
	// Prev is the MAC (hex) of the entry before it in the chain; empty for
	// the first.
	Prev string `json:"prev"`
	// KID names the key of the MAC: that of a hub CA generation.
	KID string `json:"kid"`
	// MAC is the HMAC-SHA256 (hex) of the entry and the fields above but KID.
	MAC string `json:"mac"`
}

// AuditSealer seals and checks audit entries with keys derived from the hub
// CA key (pki.AuditKeyring).
type AuditSealer interface {
	// MAC returns the MAC of msg and the id of its key; it fails on a hub
	// without the CA key.
	MAC(msg []byte) (kid string, mac []byte, err error)
	// Check reports whether mac is the MAC of msg under the key kid, and
	// whether the key is known at all.
	Check(kid string, msg, mac []byte) (known, ok bool)
	// CanVerify reports whether the sealer holds a key: whether this hub can
	// seal and check entries.
	CanVerify() bool
}

// sealerBox holds an AuditSealer in an atomic.Pointer.
type sealerBox struct{ s AuditSealer }

// SetAuditSealer makes the store seal the audit entries it appends and check
// those it reads with sealer; nil stops it. A hub sets it before it appends
// its first entry.
func (s *Store) SetAuditSealer(sealer AuditSealer) {
	if sealer == nil {
		s.sealer.Store(nil)
		return
	}
	s.sealer.Store(&sealerBox{s: sealer})
}

func (s *Store) auditSealer() AuditSealer {
	if b := s.sealer.Load(); b != nil {
		return b.s
	}
	return nil
}

// The verification of an entry, as Query returns it in AuditEntry.Verification.
const (
	// AuditVerified: the seal checks.
	AuditVerified = "verified"
	// AuditUnverified: the seal does not check, names a key this hub does
	// not know, or the entry has none although written after this database
	// started sealing: forged, changed, or written by a member without the
	// hub CA key.
	AuditUnverified = "unverified"
	// AuditLegacy: an entry without a seal, written before this database
	// started sealing.
	AuditLegacy = "legacy"
	// AuditUnchecked: the entry has a seal, but this hub holds no key to
	// check it with (a storage-only member).
	AuditUnchecked = "unchecked"
)

// verificationRank orders verifications from the best: an entry folded with
// its outcome has the worst of the two.
var verificationRank = map[string]int{AuditVerified: 0, AuditLegacy: 1, AuditUnchecked: 2, AuditUnverified: 3}

func worseVerification(a, b string) string {
	if verificationRank[b] > verificationRank[a] {
		return b
	}
	return a
}

// auditRaw is an audit entry as stored: what its MAC covers, and its seal.
type auditRaw struct {
	TS                                 int64
	ActorKind, ActorID, Action, Target string
	Decision, Result, Detail, Key      string
	Origin                             string
	Seq                                int64
	Prev, KID, MAC                     string
}

// message is what an entry's MAC covers: its columns and its place in the
// chain, each length-prefixed. The key id is not in it: another key gives
// another MAC.
func (r auditRaw) message() []byte {
	var b bytes.Buffer
	b.WriteString("hearth audit entry v1")
	for _, f := range []string{
		r.Origin, strconv.FormatInt(r.Seq, 10), r.Prev, strconv.FormatInt(r.TS, 10),
		r.ActorKind, r.ActorID, r.Action, r.Target, r.Decision, r.Result, r.Detail, r.Key,
	} {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(f))) //nolint:gosec // an entry is far below 4 GiB
		b.WriteString(f)
	}
	return b.Bytes()
}

// verify returns the verification of r: since is when this database started
// sealing (unix ms), sealer checks the MAC (nil: no key here).
func (r auditRaw) verify(since int64, sealer AuditSealer) string {
	if r.MAC == "" {
		if r.TS < since {
			return AuditLegacy
		}
		return AuditUnverified
	}
	if sealer == nil || !sealer.CanVerify() {
		return AuditUnchecked
	}
	mac, err := hex.DecodeString(r.MAC)
	if err != nil || r.Origin == "" || r.Seq <= 0 {
		return AuditUnverified
	}
	if _, ok := sealer.Check(r.KID, r.message(), mac); ok {
		return AuditVerified
	}
	return AuditUnverified
}

// rawOutcome decodes the JSON array of an outcome entry's columns a page
// query selects (auditRawArray); "" is none.
func rawOutcome(s string) (auditRaw, bool, error) {
	if s == "" {
		return auditRaw{}, false, nil
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var vals []any
	if err := dec.Decode(&vals); err != nil || len(vals) != 14 {
		return auditRaw{}, false, fmt.Errorf("decode an outcome entry: %w", errors.Join(err, errors.New("bad columns")))
	}
	str := func(i int) string { v, _ := vals[i].(string); return v }
	num := func(i int) int64 {
		n, _ := vals[i].(json.Number)
		v, _ := n.Int64()
		return v
	}
	return auditRaw{
		TS: num(0), ActorKind: str(1), ActorID: str(2), Action: str(3), Target: str(4), Decision: str(5),
		Result: str(6), Detail: str(7), Key: str(8), Origin: str(9), Seq: num(10), Prev: str(11), KID: str(12), MAC: str(13),
	}, true, nil
}

// auditRawArray selects the columns of the outcome entry o as a JSON array,
// in rawOutcome's order.
const auditRawArray = `json_array(o.ts, o.actor_kind, o.actor_id, o.action, o.target, o.decision, o.result, o.detail,
	coalesce(o.audit_key, ''), coalesce(o.chain_origin, ''), coalesce(o.chain_seq, 0), coalesce(o.chain_prev, ''),
	coalesce(o.chain_kid, ''), coalesce(o.chain_mac, ''))`

// auditSince returns when this database started sealing (unix ms): an entry
// without a seal is legacy only if older. Below schema 44, never.
func (s *Store) auditSince(ctx context.Context) (int64, error) {
	if v := s.chain.since.Load(); v != 0 {
		return v, nil
	}
	ok, err := atSchema(ctx, s.db, auditChainSchema)
	if err != nil {
		return 0, err
	}
	since := int64(math.MaxInt64)
	if ok {
		// goose's tstamp is UTC, to the second.
		if err := s.db.QueryRowContext(ctx, `SELECT coalesce(max(CAST(strftime('%s', tstamp) AS INTEGER)), 0) * 1000
			FROM goose_db_version WHERE version_id = ? AND is_applied`, auditChainSchema).Scan(&since); err != nil {
			return 0, fmt.Errorf("read when the audit log started sealing: %w", err)
		}
		s.chain.since.Store(since)
	}
	return since, nil
}

// auditChain is this member's own chain: the head its next sealed entry
// follows. mu serializes sealed appends, so the chain has no fork: an entry
// is sealed, applied, and only then does the head move on to it.
type auditChain struct {
	mu     sync.Mutex
	loaded bool
	seq    int64
	mac    string
	// since caches auditSince.
	since atomic.Int64
}

// sealsAudit reports whether the store's appends are sealed: it has a
// sealer holding a key, and every member writes the seal columns.
func (s *Store) sealsAudit(ctx context.Context) (AuditSealer, error) {
	sealer := s.auditSealer()
	if sealer == nil || !sealer.CanVerify() {
		return nil, nil
	}
	v, err := schemaVersion(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if s.writeSchema != nil {
		v = min(v, s.writeSchema())
	}
	if v < auditChainSchema {
		return nil, nil
	}
	return sealer, nil
}

// appendSealed seals c (with once-key key) as the next entry of this
// member's chain and applies it. The head moves on only once the entry is
// applied: a write that failed leaves no gap.
func (r Audit) appendSealed(ctx context.Context, c AppendAudit, key string, sealer AuditSealer) (int64, error) {
	ch := &r.s.chain
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if err := ch.load(ctx, r.s, sealer); err != nil {
		return 0, fmt.Errorf("append audit %s: %w", c.Action, err)
	}
	raw := auditRaw{
		TS: c.TS, ActorKind: c.ActorKind, ActorID: c.ActorID, Action: c.Action, Target: c.Target,
		Decision: c.Decision, Result: c.Result, Detail: c.Detail, Key: key,
		Origin: r.s.origin, Seq: ch.seq + 1, Prev: ch.mac,
	}
	kid, mac, err := sealer.MAC(raw.message())
	if err != nil {
		return 0, fmt.Errorf("append audit %s: seal: %w", c.Action, err)
	}
	raw.KID, raw.MAC = kid, hex.EncodeToString(mac)
	c.Seal = &AuditSeal{Origin: raw.Origin, Seq: raw.Seq, Prev: raw.Prev, KID: raw.KID, MAC: raw.MAC}
	res, err := r.s.apply(ctx, auditCommand(c, key))
	if err != nil {
		return 0, fmt.Errorf("append audit %s: %w", c.Action, err)
	}
	ch.seq, ch.mac = raw.Seq, raw.MAC
	return res.ID, nil
}

// auditCommand is the command appending c, with once-key key if set.
func auditCommand(c AppendAudit, key string) Command {
	if key != "" {
		return AppendAuditOnce{AppendAudit: c, Key: key}
	}
	return c
}

// auditHeadSQL selects the newest entries of a chain after a sequence
// number: the head is the newest whose seal checks.
const auditHeadSQL = `SELECT ` + auditRawCols + ` FROM audit_log
	WHERE chain_origin = ? AND chain_seq > ? ORDER BY chain_seq DESC LIMIT 100`

// load reads the chain's head from the log, whole in a sharded cluster: the
// newest entry of this member's chain whose seal checks. While some part of
// the log cannot be read it reads the local part, and again on the next
// append. An entry it missed comes back as a duplicate of a sequence number
// taken again, which Verify reports.
func (ch *auditChain) load(ctx context.Context, s *Store, sealer AuditSealer) error {
	if ch.loaded {
		return nil
	}
	rows, err := s.readEvery(ctx, auditHeadSQL, s.origin, ch.seq)
	whole := err == nil
	if !whole {
		if rows, err = s.readLocal(ctx, auditHeadSQL, s.origin, ch.seq); err != nil {
			return fmt.Errorf("read the audit chain head: %w", err)
		}
	}
	for _, vals := range rows {
		raw, err := scanRaw(vals)
		if err == nil && raw.Seq > ch.seq && raw.verify(0, sealer) == AuditVerified {
			ch.seq, ch.mac = raw.Seq, raw.MAC
		}
	}
	ch.loaded = whole
	return nil
}

// readLocal is readEvery on the local database only.
func (s *Store) readLocal(ctx context.Context, query string, args ...any) ([][]any, error) {
	wargs, err := wireArgs(args)
	if err != nil {
		return nil, err
	}
	rs, err := s.readOn(ctx, s.db, query, wargs)
	if err != nil {
		return nil, err
	}
	return valuesRows(rs.Vals), nil
}

// auditRawCols selects an entry's auditRaw columns, in scanRaw's order.
const auditRawCols = `ts, actor_kind, actor_id, action, target, decision, result, detail, coalesce(audit_key, ''),
	coalesce(chain_origin, ''), coalesce(chain_seq, 0), coalesce(chain_prev, ''), coalesce(chain_kid, ''), coalesce(chain_mac, '')`

// scanRaw reads the auditRawCols of vals.
func scanRaw(vals []any) (auditRaw, error) {
	var r auditRaw
	err := scanVals(vals, []any{&r.TS, &r.ActorKind, &r.ActorID, &r.Action, &r.Target, &r.Decision, &r.Result, &r.Detail,
		&r.Key, &r.Origin, &r.Seq, &r.Prev, &r.KID, &r.MAC})
	return r, err
}
