// SPDX-License-Identifier: AGPL-3.0-only

package beszel

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

// DefaultInterval is the time between reads when ReaderConfig.Interval is
// zero.
const DefaultInterval = 5 * time.Minute

// actorID is the audit actor of a read.
const actorID = "hub/beszel"

// Snapshot states.
const (
	// StateConnecting is before the first read finishes.
	StateConnecting = "connecting"
	// StateOK is after a read that succeeded.
	StateOK = "ok"
	// StateUnavailable is after a read that failed: Systems are those of
	// the last read that succeeded, if any.
	StateUnavailable = "unavailable"
)

// Snapshot is what the last reads found.
type Snapshot struct {
	State string
	// Error is why the last read failed; "" after one that succeeded.
	Error string
	// ReadAt is when the last read that succeeded finished; zero if none
	// has.
	ReadAt  time.Time
	Systems []System
}

// Policy decides and audits a read: *policy.Engine.
type Policy interface {
	Do(ctx context.Context, req policy.Request, fn func(context.Context) error) error
}

// Lister reads the systems: *Client.
type Lister interface {
	Target() string
	Systems(ctx context.Context) ([]System, error)
}

// ReaderConfig holds a Reader's dependencies and settings.
type ReaderConfig struct {
	Client Lister
	// Interval is the time between reads; DefaultInterval if zero.
	Interval time.Duration
	Policy   Policy
	Log      *slog.Logger
}

// Reader reads a Beszel hub every Interval and keeps what it found in
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
			r.log.WarnContext(ctx, "beszel read failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Read reads the systems once, through policy (beszel.read, class read,
// one audit entry per read), and updates the snapshot.
func (r *Reader) Read(ctx context.Context) error {
	target := r.cfg.Client.Target()
	detail := map[string]any{}
	err := r.cfg.Policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorHub,
		ActorID:   actorID,
		Action:    policy.BeszelRead,
		Target:    target,
		Detail:    detail,
		// What the read found is what this entry is for.
		RecordOutcome: true,
	}, func(ctx context.Context) error {
		start := r.now()
		systems, err := r.cfg.Client.Systems(ctx)
		if err != nil {
			return err
		}
		slices.SortFunc(systems, func(a, b System) int {
			return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
		})
		took := r.now().Sub(start)
		detail["systems"], detail["duration_ms"] = len(systems), took.Milliseconds()
		r.mu.Lock()
		r.snap = Snapshot{State: StateOK, ReadAt: r.now(), Systems: systems}
		r.mu.Unlock()
		r.log.InfoContext(ctx, "beszel read", "target", target, "systems", len(systems), "took", took.Round(time.Millisecond))
		return nil
	})
	if err != nil {
		if ctx.Err() == nil {
			r.mu.Lock()
			r.snap.State, r.snap.Error = StateUnavailable, err.Error()
			r.mu.Unlock()
		}
		return fmt.Errorf("beszel read: %w", err)
	}
	return nil
}

// Snapshot returns what the last reads found. Its Systems are a copy.
func (r *Reader) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.snap
	s.Systems = slices.Clone(s.Systems)
	return s
}
