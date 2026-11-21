// SPDX-License-Identifier: AGPL-3.0-only

package talos

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

// DefaultInterval is the time between reads when ReaderConfig.Interval is
// zero.
const DefaultInterval = time.Minute

// actorID is the audit actor of a read.
const actorID = "hub/talos"

// Snapshot states.
const (
	// StateConnecting is before the first read finishes.
	StateConnecting = "connecting"
	// StateOK is after a read that succeeded.
	StateOK = "ok"
	// StateUnavailable is after a read that failed: Nodes are those of the
	// last read that succeeded, if any.
	StateUnavailable = "unavailable"
)

// Snapshot is what the last reads found.
type Snapshot struct {
	State string
	// Error is why the last read failed; "" after one that succeeded.
	Error string
	// ReadAt is when the last read that succeeded finished; zero if none
	// has.
	ReadAt time.Time
	Nodes  []Node
}

// Policy decides and audits a read: *policy.Engine.
type Policy interface {
	Do(ctx context.Context, req policy.Request, fn func(context.Context) error) error
}

// NodeReader reads the nodes: *Client.
type NodeReader interface {
	Target() string
	Read(ctx context.Context) ([]Node, error)
}

// ReaderConfig holds a Reader's dependencies and settings.
type ReaderConfig struct {
	Client NodeReader
	// Interval is the time between reads; DefaultInterval if zero.
	Interval time.Duration
	Policy   Policy
	Log      *slog.Logger
}

// Reader reads the Talos nodes every Interval and keeps what it found in
// memory. It stores nothing.
type Reader struct {
	cfg ReaderConfig
	log *slog.Logger
	now func() time.Time

	mu   sync.Mutex
	snap Snapshot
}

// NewReader returns a reader. Call Run to start reading.
func NewReader(cfg ReaderConfig) *Reader {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Reader{cfg: cfg, log: log, now: time.Now, snap: Snapshot{State: StateConnecting}}
}

// Run reads at once and then every Interval until ctx is done. A failed
// read is logged; the next one runs on schedule.
func (r *Reader) Run(ctx context.Context) error {
	t := time.NewTicker(r.cfg.Interval)
	defer t.Stop()
	for {
		if err := r.Read(ctx); err != nil && ctx.Err() == nil {
			r.log.WarnContext(ctx, "talos read failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Read reads the nodes once, through policy (talos.read, class read, one
// audit entry per read), and updates the snapshot.
func (r *Reader) Read(ctx context.Context) error {
	target := r.cfg.Client.Target()
	detail := map[string]any{}
	err := r.cfg.Policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorHub,
		ActorID:   actorID,
		Action:    policy.TalosRead,
		Target:    target,
		Detail:    detail,
		// What the read found is what this entry is for.
		RecordOutcome: true,
	}, func(ctx context.Context) error {
		start := r.now()
		nodes, err := r.cfg.Client.Read(ctx)
		if err != nil {
			return err
		}
		took := r.now().Sub(start)
		failed := 0
		for _, n := range nodes {
			if n.Error != "" {
				failed++
			}
		}
		detail["nodes"], detail["unreachable"], detail["duration_ms"] = len(nodes), failed, took.Milliseconds()
		r.setSnapshot(Snapshot{State: StateOK, ReadAt: r.now(), Nodes: nodes})
		r.log.InfoContext(ctx, "talos read", "target", target, "nodes", len(nodes), "unreachable", failed,
			"took", took.Round(time.Millisecond))
		return nil
	})
	if err != nil {
		if ctx.Err() == nil {
			r.mu.Lock()
			r.snap.State, r.snap.Error = StateUnavailable, err.Error()
			r.mu.Unlock()
		}
		return fmt.Errorf("talos read: %w", err)
	}
	return nil
}

func (r *Reader) setSnapshot(s Snapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snap = s
}

// Snapshot returns what the last reads found. Its Nodes are a copy.
func (r *Reader) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.snap
	s.Nodes = slices.Clone(s.Nodes)
	for i := range s.Nodes {
		s.Nodes[i].Services = slices.Clone(s.Nodes[i].Services)
	}
	return s
}
