// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// RunLogFile holds the runs of local rules no hub has acknowledged yet, as
// protojson of agentv1.LocalRuns (0600). It is written only when a rule
// runs and when a hub acknowledges runs.
const RunLogFile = "localruns.json"

const (
	// maxRunLog bounds the runs kept for the hub: the oldest go first, and
	// are counted as dropped.
	maxRunLog = 100
	// maxRunLogFile bounds what is read of RunLogFile.
	maxRunLogFile = 4 << 20
	// runsResend is how long the agent waits for an acknowledgement before
	// it sends its runs again.
	runsResend = 30 * time.Second
)

// runLog is the bounded log of local rule runs, kept until a hub
// acknowledges them.
type runLog struct {
	dataDir string
	log     *slog.Logger
	// wake tells sendLoop there is something to send.
	wake chan struct{}

	mu      sync.Mutex
	runs    []*agentv1.LocalRun
	dropped uint64
	lastSeq uint64
	// sentAt is when the runs were last sent, sentSeq the newest sent;
	// zero when they wait to be sent.
	sentAt  time.Time
	sentSeq uint64
}

// openRunLog loads the runs saved in dataDir. A file that cannot be read
// is logged and starts an empty log.
func openRunLog(ctx context.Context, dataDir string, log *slog.Logger) *runLog {
	l := &runLog{dataDir: dataDir, log: log, wake: make(chan struct{}, 1)}
	saved, err := readRunLog(dataDir)
	if err != nil {
		log.WarnContext(ctx, "ignoring the saved local rule runs", "err", err)
		return l
	}
	l.runs, l.dropped = saved.GetRuns(), saved.GetDropped()
	for _, r := range l.runs {
		l.lastSeq = max(l.lastSeq, r.GetSeq())
	}
	if len(l.runs) > 0 {
		l.signal()
	}
	return l
}

func readRunLog(dataDir string) (*agentv1.LocalRuns, error) {
	f, err := os.Open(filepath.Join(dataDir, RunLogFile))
	if errors.Is(err, os.ErrNotExist) {
		return &agentv1.LocalRuns{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", RunLogFile, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRunLogFile+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", RunLogFile, err)
	}
	if len(b) > maxRunLogFile {
		return nil, fmt.Errorf("read %s: larger than %d bytes", RunLogFile, maxRunLogFile)
	}
	out := &agentv1.LocalRuns{}
	if err := protojson.Unmarshal(b, out); err != nil {
		return nil, fmt.Errorf("read %s: %w", RunLogFile, err)
	}
	if len(out.Runs) > maxRunLog {
		out.Dropped += uint64(len(out.Runs) - maxRunLog) //nolint:gosec // positive: more runs than maxRunLog
		out.Runs = out.Runs[len(out.Runs)-maxRunLog:]
	}
	return out, nil
}

func (l *runLog) signal() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

// saveLocked writes the log. The caller holds mu.
func (l *runLog) saveLocked(ctx context.Context) {
	b, err := protojson.Marshal(&agentv1.LocalRuns{Runs: l.runs, Dropped: l.dropped})
	if err == nil {
		err = replaceFile(l.dataDir, RunLogFile, append(b, '\n'))
	}
	if err != nil {
		// Not fatal: the runs in memory are sent all the same.
		l.log.WarnContext(ctx, "save the local rule runs", "err", err)
	}
}

// add logs run, with the next sequence number, and wakes sendLoop.
func (l *runLog) add(ctx context.Context, run *agentv1.LocalRun) {
	l.mu.Lock()
	// Sequence numbers grow across restarts too: an acknowledgement for
	// the runs of an earlier process never covers a new one.
	l.lastSeq = max(l.lastSeq+1, uint64(time.Now().UnixNano()))
	run.Seq = l.lastSeq
	l.runs = append(l.runs, run)
	if n := len(l.runs) - maxRunLog; n > 0 {
		l.runs = slices.Delete(l.runs, 0, n)
		l.dropped += uint64(n)
	}
	l.saveLocked(ctx)
	l.mu.Unlock()
	l.signal()
}

// next is the message to send now, or nil: the runs not acknowledged,
// unless they were sent less than runsResend ago and nothing was added
// since.
func (l *runLog) next(now time.Time) *agentv1.AgentMessage {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.runs) == 0 {
		return nil
	}
	newest := l.runs[len(l.runs)-1].GetSeq()
	if !l.sentAt.IsZero() && now.Sub(l.sentAt) < runsResend && l.sentSeq == newest {
		return nil
	}
	l.sentAt, l.sentSeq = now, newest
	return &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_LocalRuns{LocalRuns: &agentv1.LocalRuns{
		Runs: slices.Clone(l.runs), Dropped: l.dropped,
	}}}
}

// resend makes the next session send the runs at once.
func (l *runLog) resend() {
	l.mu.Lock()
	l.sentAt = time.Time{}
	pending := len(l.runs) > 0
	l.mu.Unlock()
	if pending {
		l.signal()
	}
}

// ack drops the runs up to seq: a hub recorded them.
func (l *runLog) ack(ctx context.Context, seq uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(l.runs)
	l.runs = slices.DeleteFunc(l.runs, func(r *agentv1.LocalRun) bool { return r.GetSeq() <= seq })
	if len(l.runs) == n && l.dropped == 0 {
		return
	}
	l.dropped = 0
	l.saveLocked(ctx)
	if len(l.runs) > 0 {
		// The hub takes a bounded number at a time: send the rest.
		l.sentAt = time.Time{}
		l.signal()
	}
}
