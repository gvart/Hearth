// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// Local rules (#70): automations the hub pushes for this device to run
// itself, so that a check such as a DNS watchdog keeps working while no hub
// is reachable. The agent saves them in RulesFile, loads them at startup
// before any hub connects, and runs them whether or not it is connected. A
// rule's checks fire it after failing for its hold, once per outage; its
// actions (restart a service, run a check) run in order, the first failure
// ending the run. Every probe and restart is checked against the effective
// ceiling when it runs: what the hub allowed when it pushed the rule is not
// enough. Each run goes to the run log (runlog.go), which the agent sends
// to the hub when it can.

// RulesFile holds the local rules the hub last set for this device, as
// protojson of agentv1.LocalRules (0600).
const RulesFile = "rules.json"

const (
	// maxRulesFile bounds what is read of RulesFile.
	maxRulesFile = 1 << 20
	// maxRules, maxRuleSteps bound a rule set.
	maxRules     = 64
	maxRuleSteps = 64
	// minRuleEvery keeps a rule from checking in a tight loop.
	minRuleEvery = time.Second
	// defaultRuleEvery applies to a check that sets no interval.
	defaultRuleEvery = 10 * time.Second
)

// ruleIDPattern is what automation and step ids look like.
var ruleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// checkRules refuses a rule set the agent cannot run: one bad rule refuses
// all of it, as one bad ceiling entry does.
func checkRules(rs *agentv1.LocalRules) error {
	if len(rs.GetRules()) > maxRules {
		return fmt.Errorf("more than %d rules", maxRules)
	}
	seen := map[string]bool{}
	for _, r := range rs.GetRules() {
		if !ruleIDPattern.MatchString(r.GetId()) || seen[r.GetId()] {
			return fmt.Errorf("rule id %q is not a unique automation id", r.GetId())
		}
		seen[r.GetId()] = true
		if len(r.GetTriggers()) == 0 || len(r.GetActions()) == 0 || len(r.GetTriggers())+len(r.GetActions()) > maxRuleSteps {
			return fmt.Errorf("rule %s: needs 1 to %d steps, with a trigger and an action", r.GetId(), maxRuleSteps)
		}
		for _, t := range r.GetTriggers() {
			if !ruleIDPattern.MatchString(t.GetId()) || t.GetProbe().GetProbe() == nil {
				return fmt.Errorf("rule %s: trigger %q is not a check", r.GetId(), t.GetId())
			}
		}
		for _, a := range r.GetActions() {
			if !ruleIDPattern.MatchString(a.GetId()) {
				return fmt.Errorf("rule %s: bad action id %q", r.GetId(), a.GetId())
			}
			switch {
			case a.GetRestart() != nil && a.GetRestart().GetName() != "":
			case a.GetCheck().GetProbe() != nil:
			default:
				return fmt.Errorf("rule %s: action %s is neither a restart nor a check", r.GetId(), a.GetId())
			}
		}
	}
	return nil
}

// readRulesFile returns the rules saved in dataDir, checked, or none.
func readRulesFile(dataDir string) (*agentv1.LocalRules, error) {
	f, err := os.Open(filepath.Join(dataDir, RulesFile))
	if errors.Is(err, os.ErrNotExist) {
		return &agentv1.LocalRules{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", RulesFile, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRulesFile+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", RulesFile, err)
	}
	if len(b) > maxRulesFile {
		return nil, fmt.Errorf("read %s: larger than %d bytes", RulesFile, maxRulesFile)
	}
	rs := &agentv1.LocalRules{}
	if err := protojson.Unmarshal(b, rs); err != nil {
		return nil, fmt.Errorf("read %s: %w", RulesFile, err)
	}
	if err := checkRules(rs); err != nil {
		return nil, fmt.Errorf("read %s: %w", RulesFile, err)
	}
	return rs, nil
}

// writeRulesFile replaces the rules saved in dataDir (0600) atomically.
func writeRulesFile(dataDir string, rs *agentv1.LocalRules) error {
	b, err := protojson.Marshal(rs)
	if err != nil {
		return fmt.Errorf("write %s: %w", RulesFile, err)
	}
	if err := replaceFile(dataDir, RulesFile, append(b, '\n')); err != nil {
		return fmt.Errorf("write %s: %w", RulesFile, err)
	}
	return nil
}

// rules runs the local rules. Run owns it: start it once, and stop it
// before Run returns.
type rules struct {
	dataDir string
	log     *slog.Logger
	ceiling func() Ceiling
	// connected says whether a hub stream is open.
	connected func() bool
	runs      *runLog
	now       func() time.Time

	// mu guards what follows; apply and stop take it.
	mu      sync.Mutex
	ctx     context.Context //nolint:containedctx // Run's, which every rule's goroutines live in
	wg      sync.WaitGroup
	version uint64
	live    map[string]*liveRule
}

// liveRule is one running rule: its triggers' goroutines.
type liveRule struct {
	rule   *agentv1.LocalRule
	cancel context.CancelFunc
	done   chan struct{}
	// running is held while a run is in progress: a check that fires
	// meanwhile is ignored.
	running sync.Mutex
}

// start runs rs, the saved rules, until ctx is done.
func (e *rules) start(ctx context.Context, rs *agentv1.LocalRules) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ctx, e.live, e.version = ctx, map[string]*liveRule{}, rs.GetVersion()
	e.reconcile(rs)
}

// stop ends every rule and waits for them.
func (e *rules) stop() {
	e.mu.Lock()
	for _, l := range e.live {
		l.cancel()
	}
	e.live = map[string]*liveRule{}
	e.mu.Unlock()
	e.wg.Wait()
}

// apply takes the rules the hub sent: unless they are older than the ones
// applied, or invalid, it saves them and runs them, stopping the rules that
// went or changed.
func (e *rules) apply(ctx context.Context, rs *agentv1.LocalRules) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if rs.GetVersion() < e.version {
		e.log.InfoContext(ctx, "older local rules from the hub ignored", "version", rs.GetVersion(), "applied", e.version)
		return
	}
	if err := checkRules(rs); err != nil {
		e.log.WarnContext(ctx, "local rules from the hub refused", "err", err)
		return
	}
	e.version = rs.GetVersion()
	if err := writeRulesFile(e.dataDir, rs); err != nil {
		// Not fatal: the rules in memory run, and the hub sends them
		// again on the next connect.
		e.log.WarnContext(ctx, "save the local rules", "err", err)
	}
	e.reconcile(rs)
}

// reconcile makes rs the running rules. The caller holds mu.
func (e *rules) reconcile(rs *agentv1.LocalRules) {
	if e.ctx == nil {
		return // not started
	}
	next := map[string]*liveRule{}
	for _, r := range rs.GetRules() {
		if l, ok := e.live[r.GetId()]; ok && proto.Equal(l.rule, r) {
			next[r.GetId()] = l
			delete(e.live, r.GetId())
			continue
		}
		next[r.GetId()] = nil
	}
	// Stop what changed or went before its replacement starts, so two
	// versions of a rule never run at once.
	for id, l := range e.live {
		l.cancel()
		<-l.done
		e.log.InfoContext(e.ctx, "local rule stopped", "automation", id)
	}
	for _, r := range rs.GetRules() {
		if next[r.GetId()] == nil {
			next[r.GetId()] = e.run(r)
			e.log.InfoContext(e.ctx, "local rule started", "automation", r.GetId(), "triggers", len(r.GetTriggers()),
				"actions", len(r.GetActions()))
		}
	}
	e.live = next
}

// run starts the goroutines of r's triggers.
func (e *rules) run(r *agentv1.LocalRule) *liveRule {
	ctx, cancel := context.WithCancel(e.ctx)
	l := &liveRule{rule: proto.CloneOf(r), cancel: cancel, done: make(chan struct{})}
	var wg sync.WaitGroup
	for _, t := range l.rule.GetTriggers() {
		wg.Go(func() { e.watch(ctx, l, t) })
	}
	e.wg.Go(func() {
		wg.Wait()
		close(l.done)
	})
	return l
}

// watch runs the check t every interval, and fires l once t has failed for
// its hold, once per outage. A check the ceiling does not allow changes
// nothing: it neither fires nor ends an outage.
func (e *rules) watch(ctx context.Context, l *liveRule, t *agentv1.LocalTrigger) {
	every := t.GetEvery().AsDuration()
	if every <= 0 {
		every = defaultRuleEvery
	}
	every = max(every, minRuleEvery)
	hold := t.GetHold().AsDuration()
	var (
		badSince time.Time
		fired    bool
		refused  bool // logged once per spell
	)
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		res := e.ceiling().probe(ctx, t.GetProbe())
		switch {
		case ctx.Err() != nil:
			return
		case res.GetDenied():
			if !refused {
				e.log.WarnContext(ctx, "local rule check refused: beyond the capability ceiling",
					"automation", l.rule.GetId(), "trigger", t.GetId())
				refused = true
			}
		case res.GetError() == "":
			badSince, fired, refused = time.Time{}, false, false
		default:
			refused = false
			now := e.now()
			if badSince.IsZero() {
				badSince = now
			}
			if !fired && now.Sub(badSince) >= hold {
				fired = true
				e.fire(ctx, l, t, res.GetError())
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// fire runs l's actions for the failed check t, unless a run is in
// progress, and logs the run.
func (e *rules) fire(ctx context.Context, l *liveRule, t *agentv1.LocalTrigger, why string) {
	if !l.running.TryLock() {
		e.log.InfoContext(ctx, "local rule already running; trigger ignored", "automation", l.rule.GetId(), "trigger", t.GetId())
		return
	}
	defer l.running.Unlock()
	run := &agentv1.LocalRun{
		Id: "local-" + strings.ToLower(rand.Text()), Rule: l.rule.GetId(), Trigger: t.GetId(), TriggerType: t.GetType(),
		Target: t.GetTarget(), TriggerError: why, Started: timestamppb.New(e.now()), HubConnected: e.connected(),
		Status: "succeeded",
	}
	for _, a := range l.rule.GetActions() {
		step := e.act(ctx, a)
		run.Steps = append(run.Steps, step)
		if step.GetStatus() != "ok" {
			run.Status, run.Error = "failed", a.GetId()+": "+step.GetError()
			if step.GetStatus() == "denied" {
				run.Status = "denied"
			}
			break
		}
	}
	run.Finished = timestamppb.New(e.now())
	// Never the check's URL: its target is redacted, its error is the
	// check's own.
	e.log.InfoContext(ctx, "local rule ran", "automation", run.GetRule(), "trigger", run.GetTrigger(),
		"status", run.GetStatus(), "hub_connected", run.GetHubConnected())
	e.runs.add(ctx, run)
}

// act takes one action, within the ceiling.
func (e *rules) act(ctx context.Context, a *agentv1.LocalAction) *agentv1.LocalStep {
	step := &agentv1.LocalStep{Id: a.GetId(), Type: a.GetType(), Status: "ok"}
	switch {
	case a.GetRestart() != nil:
		res := e.ceiling().execute(ctx, &agentv1.ExecRequest{
			Id: a.GetId(), Timeout: a.GetTimeout(), Action: &agentv1.ExecRequest_Restart{Restart: a.GetRestart()},
		})
		switch {
		case res.GetDenied():
			step.Status, step.Error = "denied", res.GetError()
		case res.GetError() != "":
			step.Status, step.Error = "failed", res.GetError()
		case res.GetExitCode() != 0:
			step.Status, step.Error = "failed", fmt.Sprintf("exit status %d", res.GetExitCode())
		}
	case a.GetCheck() != nil:
		req := proto.CloneOf(a.GetCheck())
		if req.Timeout == nil {
			req.Timeout = durationpb.New(defaultProbeTimeout)
		}
		res := e.ceiling().probe(ctx, req)
		switch {
		case res.GetDenied():
			step.Status, step.Error = "denied", res.GetError()
		case res.GetError() != "":
			step.Status, step.Error = "failed", res.GetError()
		}
	}
	return step
}

// startRules runs the saved local rules, before any hub connects. A file
// that cannot be read runs no rules: the hub sends them again on connect.
func (r *runner) startRules(ctx context.Context) {
	r.runs = openRunLog(ctx, r.cfg.DataDir, r.log)
	r.rules = &rules{
		dataDir: r.cfg.DataDir, log: r.log, ceiling: r.ceiling, connected: r.connected.Load, runs: r.runs, now: time.Now,
	}
	saved, err := readRulesFile(r.cfg.DataDir)
	if err != nil {
		r.log.WarnContext(ctx, "ignoring the saved local rules; running none until a hub sends them", "err", err)
		saved = &agentv1.LocalRules{}
	}
	r.rules.start(ctx, saved)
}
