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

// fsm applies committed log entries to the store.
type fsm struct {
	st      *store.Store
	dir     string
	log     *slog.Logger
	onFatal func(error)

	mu     sync.Mutex
	halted error
}

var _ raft.FSM = (*fsm)(nil)

func newFSM(st *store.Store, dir string, log *slog.Logger, onFatal func(error)) *fsm {
	return &fsm{st: st, dir: dir, log: log, onFatal: onFatal}
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
