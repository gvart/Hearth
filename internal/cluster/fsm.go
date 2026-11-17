// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/raft"

	"github.com/gvart/hearth/internal/store"
)

// ErrHalted is returned for every entry after the state machine failed to
// apply one: the node no longer follows the log and must be restarted.
var ErrHalted = errors.New("cluster: state machine halted after a failed apply; restart the hub")

// applyResponse is what fsm.Apply returns to raft, and so to the proposer.
type applyResponse struct {
	res store.Result
	err error
}

// ApplyObserver is told about every command this node's state machine
// applies. Both methods run on raft's apply goroutine, in log order, so they
// must return quickly and never block (no waiting on Raft writes, no
// unbounded I/O): a slow observer stalls replication on this node.
type ApplyObserver interface {
	// Applied is called after cmd was applied successfully (a domain error
	// is not reported). local is true when this node proposed the entry: it
	// was the leader of the entry's Raft term when it applied it. A leader
	// that already reacted to its own writes uses it to skip them.
	Applied(cmd store.Command, res store.Result, local bool)
	// Restored is called after a snapshot replaced the whole store. No
	// Applied calls are made for what the snapshot contains, so anything
	// derived from earlier entries must be rebuilt from the store.
	Restored()
}

// fsm applies committed log entries to the store.
type fsm struct {
	st      *store.Store
	dir     string
	log     *slog.Logger
	onFatal func(error)
	// obs is the node's ApplyObserver, if any (see Node.ObserveApplies).
	obs *atomic.Pointer[ApplyObserver]
	// raft is set once raft.NewRaft returns; nil before.
	raft atomic.Pointer[raft.Raft]

	// applied is the index of the last command entry the store reflects:
	// the last one Apply applied, or the index of the snapshot Restore
	// installed. Raft's own AppliedIndex moves when entries are handed to the
	// FSM, before the store has them (see Node.appliedThrough).
	applied atomic.Uint64
	// snaps is the node's snapshot store, read by Restore for the index of
	// the snapshot it installs; nil in unit tests.
	snaps raft.SnapshotStore

	mu     sync.Mutex
	halted error
}

var _ raft.FSM = (*fsm)(nil)

func newFSM(st *store.Store, dir string, log *slog.Logger, onFatal func(error), obs *atomic.Pointer[ApplyObserver]) *fsm {
	return &fsm{st: st, dir: dir, log: log, onFatal: onFatal, obs: obs}
}

// ledTerm reports whether this node is the leader of term now. Only the
// leader of a term appends entries of that term, so an entry of that term
// applied while this holds was proposed here. A leader that stepped down
// before applying its entry answers false; its proposer got an error.
func (f *fsm) ledTerm(term uint64) bool {
	r := f.raft.Load()
	return r != nil && r.State() == raft.Leader && r.CurrentTerm() == term
}

func (f *fsm) observer() ApplyObserver {
	if f.obs == nil {
		return nil
	}
	if o := f.obs.Load(); o != nil {
		return *o
	}
	return nil
}

// Apply decodes the entry and applies it with ApplyLocal. A domain error (the
// command's own outcome, the same on every node) goes back to the proposer.
// Any other error means this node could not apply what the others did: the
// state machine halts rather than drift, and OnFatal tells the hub to stop.
func (f *fsm) Apply(l *raft.Log) any {
	if err := f.haltedErr(); err != nil {
		return applyResponse{err: err}
	}
	cmd, err := store.DecodeCommand(l.Data)
	if err != nil {
		return applyResponse{err: f.halt(fmt.Errorf("log entry %d: %w", l.Index, err))}
	}
	res, err := f.st.ApplyLocal(context.Background(), cmd)
	if err != nil && !store.IsDomainError(err) {
		return applyResponse{err: f.halt(fmt.Errorf("log entry %d (%s): %w", l.Index, cmd.Op(), err))}
	}
	f.applied.Store(l.Index)
	if o := f.observer(); err == nil && o != nil {
		o.Applied(cmd, res, f.ledTerm(l.Term))
	}
	return applyResponse{res: res, err: err}
}

func (f *fsm) haltedErr() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.halted
}

func (f *fsm) halt(cause error) error {
	f.mu.Lock()
	first := f.halted == nil
	if first {
		f.halted = fmt.Errorf("%w: %w", ErrHalted, cause)
	}
	err := f.halted
	f.mu.Unlock()
	if first {
		f.log.Error("cluster state machine halted: this hub failed to apply a committed write and stops "+
			"to avoid diverging from the cluster; fix the cause (disk full? permissions?) and restart it, "+
			"the entry is applied again from the log", "err", cause)
		f.onFatal(err)
	}
	return err
}

// Snapshot copies the database now, while raft holds applies back, so the
// copy matches the snapshot's log index exactly. Persist streams the copy
// later, concurrently with new applies.
func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	if err := f.haltedErr(); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(f.dir, ".fsm-snapshot-*.db")
	if err != nil {
		return nil, fmt.Errorf("fsm snapshot: %w", err)
	}
	if err := f.st.Snapshot(context.Background(), tmp); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, fmt.Errorf("fsm snapshot: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, fmt.Errorf("fsm snapshot: %w", err)
	}
	return &fileSnapshot{f: tmp}, nil
}

// Restore replaces the whole database with a snapshot. It runs at start (the
// latest local snapshot, before the log after it is replayed) and when the
// leader sends a snapshot to a node that is too far behind or new.
func (f *fsm) Restore(rc io.ReadCloser) error {
	defer func() { _ = rc.Close() }()
	if err := f.st.Restore(context.Background(), rc); err != nil {
		f.log.Error("cluster snapshot restore failed", "err", err)
		return err
	}
	// Raft restores the newest snapshot: at start, and when the leader sent
	// one, which raft stored before it asked for the restore.
	if f.snaps != nil {
		if metas, err := f.snaps.List(); err == nil && len(metas) > 0 {
			f.applied.Store(metas[0].Index)
		}
	}
	if o := f.observer(); o != nil {
		o.Restored()
	}
	return nil
}

type fileSnapshot struct{ f *os.File }

func (s *fileSnapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := io.Copy(sink, s.f); err != nil {
		_ = sink.Cancel()
		return fmt.Errorf("persist snapshot: %w", err)
	}
	return sink.Close()
}

func (s *fileSnapshot) Release() {
	_ = s.f.Close()
	_ = os.Remove(s.f.Name())
}
