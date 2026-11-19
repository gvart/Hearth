// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// AuditEntryLost is the action of the entry a Spool writes in place of a
// spooled entry it cannot read back: the gap is in the audit log, not only
// in the hub's own log.
const AuditEntryLost = "audit.entry_lost"

// Spool keeps, in files of a hub's own, the audit entries that report how
// something already done ended and that could not be written, typically
// because a hub cluster has no quorum. Run writes them later, with the time
// and key they were made with, so each lands once however often it is tried.
//
// Only entries written after the fact go here: an entry an action waits for
// is never spooled, as the action must not run without it (see Engine.run).
type Spool struct {
	dir   string
	audit Auditor
	log   *slog.Logger
	wake  chan struct{}
	// retryMin and retryMax bound the wait between attempts while entries
	// are left.
	retryMin, retryMax time.Duration
	// timeout bounds one attempt at writing an entry.
	timeout time.Duration
}

// spoolExt names a whole spooled entry; one being written has spoolTmp
// added, and one that could not be read back spoolBad.
const (
	spoolExt = ".json"
	spoolTmp = ".tmp"
	spoolBad = ".bad"
)

// OpenSpool returns the spool kept in dir, created 0700 if missing, writing
// to audit.
func OpenSpool(dir string, audit Auditor, log *slog.Logger) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("open audit spool: %w", err)
	}
	return &Spool{
		dir: dir, audit: audit, log: log, wake: make(chan struct{}, 1),
		retryMin: time.Second, retryMax: 30 * time.Second, timeout: outcomeTimeout,
	}, nil
}

// spooled is an entry as a spool file holds it.
type spooled struct {
	TS        time.Time       `json:"ts"`
	ActorKind string          `json:"actor_kind"`
	ActorID   string          `json:"actor_id"`
	Action    string          `json:"action"`
	Target    string          `json:"target"`
	Decision  string          `json:"decision"`
	Result    string          `json:"result"`
	Detail    json.RawMessage `json:"detail,omitempty"`
	Key       string          `json:"key"`
}

// Put keeps e, which must carry a Key, until Run writes it. It returns once
// the entry is on disk; it works whether or not Run is running.
func (s *Spool) Put(e store.AuditEntry) error {
	if e.Key == "" || strings.ContainsAny(e.Key, `/\.`) {
		return errors.New("spool audit entry: it needs a key fit for a file name")
	}
	b, err := json.Marshal(spooled{
		TS: e.TS, ActorKind: e.ActorKind, ActorID: e.ActorID, Action: e.Action, Target: e.Target,
		Decision: e.Decision, Result: e.Result, Detail: e.Detail, Key: e.Key,
	})
	if err != nil {
		return fmt.Errorf("spool audit entry: %w", err)
	}
	// Named by time, so Run writes entries in the order they were made.
	name := fmt.Sprintf("%020d-%s%s", e.TS.UnixNano(), e.Key, spoolExt)
	if err := s.write(name, b); err != nil {
		return fmt.Errorf("spool audit entry: %w", err)
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

// write puts b in the file name whole or not at all: written aside, synced
// and renamed into place.
func (s *Spool) write(name string, b []byte) error {
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	tmp := name + spoolTmp
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cErr := f.Close(); err == nil {
		err = cErr
	}
	if err == nil {
		err = root.Rename(tmp, name)
	}
	if err != nil {
		_ = root.Remove(tmp)
		return err
	}
	if d, err := root.Open("."); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Run writes the spooled entries at once and whenever Put adds one, and
// while any is left retries with a growing wait, until ctx is done. An entry
// stays on disk until it is written, so what is left when ctx ends is
// written by the next Run, after a restart. It returns nil when ctx is done.
func (s *Spool) Run(ctx context.Context) error {
	wait := s.retryMin
	for {
		left := s.Drain(ctx)
		if ctx.Err() != nil {
			return nil
		}
		var retry <-chan time.Time
		t := time.NewTimer(wait)
		if left {
			retry = t.C
			wait = min(2*wait, s.retryMax)
		} else {
			wait = s.retryMin
		}
		select {
		case <-ctx.Done():
		case <-s.wake:
		case <-retry:
		}
		t.Stop()
	}
}

// Drain writes the spooled entries, oldest first, and reports whether any is
// left: it stops at the first that cannot be written, as the next would fail
// the same way. A file that cannot be read back is replaced by an
// AuditEntryLost entry and set aside.
func (s *Spool) Drain(ctx context.Context) (left bool) {
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		s.log.ErrorContext(ctx, "audit spool unreadable", "err", err)
		return true
	}
	defer func() { _ = root.Close() }()
	names, err := fs.Glob(root.FS(), "*"+spoolExt)
	if err != nil {
		s.log.ErrorContext(ctx, "audit spool unreadable", "err", err)
		return true
	}
	slices.Sort(names)
	for _, name := range names {
		if ctx.Err() != nil {
			return true
		}
		if !s.drainOne(ctx, root, name) {
			return true
		}
	}
	return false
}

// drainOne writes the entry in name and removes the file, and reports whether
// it is done with it.
func (s *Spool) drainOne(ctx context.Context, root *os.Root, name string) bool {
	e, readErr := readSpooled(root, name)
	if readErr != nil {
		s.log.ErrorContext(ctx, "spooled audit entry unreadable, recording the gap", "file", name, "err", readErr)
		e = store.AuditEntry{
			TS: time.Now(), ActorKind: ActorHub, ActorID: "audit-spool", Action: AuditEntryLost,
			Decision: Allow, Result: "lost: a spooled audit entry could not be read back",
			Detail: lostDetail(name, readErr), Key: "lost-" + strings.TrimSuffix(name, spoolExt),
		}
	}
	actx, cancel := context.WithTimeout(ctx, s.timeout)
	_, err := s.audit.Append(actx, e)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			s.log.WarnContext(ctx, "spooled audit entry not written yet, will retry", "file", name, "err", err)
		}
		return false
	}
	if readErr != nil {
		err = root.Rename(name, name+spoolBad)
	} else {
		err = root.Remove(name)
	}
	if err != nil {
		// Written; its key keeps the next attempt from adding it again.
		s.log.ErrorContext(ctx, "audit spool: written entry not cleared", "file", name, "err", err)
		return false
	}
	return true
}

func readSpooled(root *os.Root, name string) (store.AuditEntry, error) {
	b, err := root.ReadFile(name)
	if err != nil {
		return store.AuditEntry{}, err
	}
	var sp spooled
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sp); err != nil {
		return store.AuditEntry{}, err
	}
	// What the audit log would refuse on every retry must not hold up the
	// entries after it.
	switch {
	case sp.Key == "" || sp.TS.IsZero():
		return store.AuditEntry{}, errors.New("no key or time")
	case sp.ActorKind == "" || sp.ActorID == "" || sp.Action == "" || sp.Decision == "":
		return store.AuditEntry{}, errors.New("no actor, action or decision")
	case len(sp.Detail) > 0 && store.AuditDetailTooDeep(sp.Detail):
		return store.AuditEntry{}, errors.New("detail nests too deep")
	}
	return store.AuditEntry{
		TS: sp.TS, ActorKind: sp.ActorKind, ActorID: sp.ActorID, Action: sp.Action, Target: sp.Target,
		Decision: sp.Decision, Result: sp.Result, Detail: sp.Detail, Key: sp.Key,
	}, nil
}

func lostDetail(name string, err error) json.RawMessage {
	b, mErr := json.Marshal(map[string]string{"spool_file": name, "error": err.Error()})
	if mErr != nil {
		return nil
	}
	return b
}
