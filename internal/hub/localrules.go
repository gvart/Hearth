// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// Local rules (#70): an automation marked `local: true` runs on the device
// its checks run from, by that device's agent, so that it keeps working
// while no hub is reachable. The hub holding the agent's stream sends the
// agent its rules in a LocalRules, as it sends the ceiling (ceilingpush.go):
// on every connect, an empty set too, and from every heartbeat when the set
// changed. Before it sends a rule it asks policy, as the automation, about
// each of its probes (automation.probe) and restarts (automation.restart),
// with the device's reported ceiling as the precheck; a rule with any step
// denied, beyond the ceiling or held for approval is not sent: a rule that
// runs while the hub is down cannot wait for one. The decisions are made
// again, and audited, only when the set or what would be decided changes.
//
// The agent reports its runs in LocalRuns. The hub records each run of an
// automation that is local to the stream's device in the audit log and run
// history, marked as run on the device (while the hub was unreachable, when
// the agent had no stream), and acknowledges them.

// minLocalRulesMinor is the first agent protocol minor version that takes
// LocalRules and sends LocalRuns.
const minLocalRulesMinor = 12

const (
	// maxLocalRunsRecorded bounds the runs of one LocalRuns the hub takes;
	// the agent sends the rest after the acknowledgement.
	maxLocalRunsRecorded = 100
	// maxLocalRunSteps bounds the steps of a run, as a save does.
	maxLocalRunSteps = automation.MaxSaveSteps
	// maxLocalRunText bounds each text a run reports.
	maxLocalRunText = 1024
	// maxLocalRunAge is how far back a reported run may start: an older
	// time is taken as wrong, and replaced by when the hub got the report.
	maxLocalRunAge = 90 * 24 * time.Hour
)

// Detail values that mark the audit entries of local rules.
const (
	localPushed      = "pushed to the device"
	localRan         = "ran on the device"
	localRanHubsDown = "ran on the device while the hub was unreachable"
)

// LocalAutomations are the local automations a hub loaded:
// *automation.Runtime.
type LocalAutomations interface {
	Local() []*automation.Automation
}

// LocalRulePolicy decides on the steps of the rules pushed: *policy.Engine.
type LocalRulePolicy interface {
	Do(ctx context.Context, req policy.Request, fn func(context.Context) error) error
	Check(req policy.Request) (decision, reason string)
}

// LocalRunRecorder keeps the run history: store.AutomationRuns.
type LocalRunRecorder interface {
	Record(ctx context.Context, run store.AutomationRun) error
	List(ctx context.Context, automationID string, limit int) ([]store.AutomationRun, error)
}

// LocalRulesConfig is what the hub needs to push local rules and record
// their runs.
type LocalRulesConfig struct {
	Automations LocalAutomations
	// Docs versions the rule sets: store.ConfigDocs.
	Docs interface {
		Version(ctx context.Context, kind string) (uint64, error)
	}
	Policy  LocalRulePolicy
	Audit   auditAppender
	Runs    LocalRunRecorder
	Devices interface {
		List(ctx context.Context) ([]store.Device, error)
	}
	Now func() time.Time
}

// SetLocalRules makes the streams of a push their devices' local rules and
// record their runs. Call it before the hub takes agent streams.
func (a *Agents) SetLocalRules(cfg LocalRulesConfig) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	a.local.Store(&cfg)
}

// localRulesState is a session's part in local rules.
type localRulesState struct {
	// mu serialises the pushes of the session; sent is the set the agent
	// last got, and key what it was decided on.
	mu   sync.Mutex
	sent *agentv1.LocalRules
	key  string
}

// syncLocalRules sends sess its device's local rules when they, or what
// policy and the ceiling say of them, changed since the last it got. A
// failure is logged: the next heartbeat tries again.
func (s *AgentStream) syncLocalRules(ctx context.Context, log *slog.Logger, sess *agentSession) {
	cfg := s.agents.local.Load()
	if cfg == nil || sess.minor < minLocalRulesMinor {
		return
	}
	if err := sess.syncLocalRules(ctx, cfg); err != nil {
		log.WarnContext(ctx, "send the device's local rules", "err", err)
	}
}

// candidate is a local automation of the session's device, with its steps.
type candidate struct {
	a     *automation.Automation
	rule  *agentv1.LocalRule
	steps []localStep
}

// localStep is a step of a local rule as policy decides on it: its checks
// as one probe, or one of its restarts.
type localStep struct {
	req     policy.Request
	restart *agentv1.RestartService // nil for the probe
}

func (s *agentSession) syncLocalRules(ctx context.Context, cfg *LocalRulesConfig) error {
	s.rules.mu.Lock()
	defer s.rules.mu.Unlock()
	// The version is read before the rules: a set read later never carries
	// an older version than one read before it.
	version, err := cfg.Docs.Version(ctx, store.ConfigAutomation)
	if err != nil {
		return fmt.Errorf("read the automations' version: %w", err)
	}
	cands, err := s.localCandidates(ctx, cfg)
	if err != nil {
		return err
	}
	// What the decisions would be, cheaply: unaudited, so that the audited
	// ones are made only when it changes.
	var key strings.Builder
	for _, c := range cands {
		fmt.Fprintf(&key, "%s\x00%s", c.rule.GetId(), c.rule.GetDigest())
		for _, st := range c.steps {
			d, _ := cfg.Policy.Check(st.req)
			fmt.Fprintf(&key, "\x00%s\x00%s\x00%t", st.req.Action, d, s.localPrecheck(st) == nil)
		}
		key.WriteByte('\n')
	}
	if s.rules.sent != nil && s.rules.key == key.String() {
		return nil
	}
	out := &agentv1.LocalRules{Version: version}
	for _, c := range cands {
		if s.decideLocal(ctx, cfg, c) {
			out.Rules = append(out.Rules, c.rule)
		}
	}
	msg := &agentv1.HubMessage{Payload: &agentv1.HubMessage_LocalRules{LocalRules: out}}
	if err := s.sendMsg(msg); err != nil {
		return err
	}
	s.rules.sent, s.rules.key = out, key.String()
	return nil
}

// localCandidates are the local automations whose checks run from the
// session's device, by id.
func (s *agentSession) localCandidates(ctx context.Context, cfg *LocalRulesConfig) ([]candidate, error) {
	local := cfg.Automations.Local()
	if len(local) == 0 {
		return nil, nil
	}
	devs, err := cfg.Devices.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	var out []candidate
	for _, a := range local {
		ref := a.LocalDevice()
		if !refersTo(devs, ref, s.device) {
			continue
		}
		r, err := a.LocalRule()
		if err != nil {
			continue
		}
		out = append(out, candidate{a: a, rule: r, steps: localSteps(r, ref, s.device)})
	}
	slices.SortFunc(out, func(x, y candidate) int { return strings.Compare(x.a.ID, y.a.ID) })
	return out, nil
}

// refersTo reports whether ref, a device id, name or hostname, names the
// device id, as findDevice would resolve it.
func refersTo(devs []store.Device, ref, id string) bool {
	for _, d := range devs {
		if d.ID == ref || d.Name == ref || strings.EqualFold(d.Hostname, ref) {
			return d.ID == id
		}
	}
	return false
}

// localSteps are the steps of r policy decides on: one probe for all its
// checks, and each restart. ref is the device as the automation names it.
func localSteps(r *agentv1.LocalRule, ref, device string) []localStep {
	detail := func(step string) map[string]any {
		return map[string]any{"step": step, "local": localPushed, "device": device}
	}
	steps := []localStep{{req: policy.Request{
		ActorKind: policy.ActorAutomation, ActorID: r.GetId(), Action: policy.AutomationProbe, Target: ref,
		Detail: detail(r.GetTriggers()[0].GetId()),
	}}}
	for _, act := range r.GetActions() {
		rs := act.GetRestart()
		if rs == nil {
			continue
		}
		d := detail(act.GetId())
		d["service"] = rs.GetManager() + ":" + rs.GetName()
		steps = append(steps, localStep{restart: rs, req: policy.Request{
			ActorKind: policy.ActorAutomation, ActorID: r.GetId(), Action: policy.AutomationRestart, Target: ref, Detail: d,
		}})
	}
	return steps
}

// localPrecheck checks st against the ceiling the agent reported.
func (s *agentSession) localPrecheck(st localStep) error {
	if st.restart != nil {
		return s.check(s.device, &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Restart{Restart: st.restart}})
	}
	return s.checkProbe(s.device)
}

// errLocalNeedsApproval denies a step of a local rule that policy would
// hold for approval: the device runs it without asking the hub.
var errLocalNeedsApproval = fmt.Errorf("a rule that runs on the device cannot wait for approval: %w", policy.ErrDenied)

// decideLocal asks policy about every step of c, audited, and reports
// whether all were allowed. It stops at the first denial.
func (s *agentSession) decideLocal(ctx context.Context, cfg *LocalRulesConfig, c candidate) bool {
	for _, st := range c.steps {
		req := st.req
		req.Precheck = func(context.Context) error {
			if err := s.localPrecheck(st); err != nil {
				return err
			}
			if d, _ := cfg.Policy.Check(req); d == policy.Confirm {
				return errLocalNeedsApproval
			}
			return nil
		}
		if err := cfg.Policy.Do(ctx, req, func(context.Context) error { return nil }); err != nil {
			return false
		}
	}
	return true
}

// runIDPattern is what a run id a device reports looks like.
var runIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// recordLocalRuns records the runs the agent reported and acknowledges
// them. A run of an automation that is not local to the device is dropped,
// logged: a device can only speak for its own rules. A run that could not
// be recorded is not acknowledged, so the agent sends it again.
func (s *AgentStream) recordLocalRuns(ctx context.Context, log *slog.Logger, sess *agentSession, msg *agentv1.LocalRuns) {
	cfg := s.agents.local.Load()
	if cfg == nil || sess.minor < minLocalRulesMinor {
		return
	}
	if n := msg.GetDropped(); n > 0 {
		log.WarnContext(ctx, "the device's log of local rule runs was full: older runs were not reported", "dropped", n)
	}
	cands, err := sess.localCandidates(ctx, cfg)
	if err != nil {
		log.WarnContext(ctx, "record the device's local rule runs", "err", err)
		return
	}
	ours := map[string]bool{}
	for _, c := range cands {
		ours[c.a.ID] = true
	}
	var acked uint64
	for i, run := range msg.GetRuns() {
		if i == maxLocalRunsRecorded {
			break
		}
		ok := true
		switch {
		case !ours[run.GetRule()]:
			log.WarnContext(ctx, "local rule run dropped: the automation does not run on this device", "automation", clip(run.GetRule()))
		case !runIDPattern.MatchString(run.GetId()):
			log.WarnContext(ctx, "local rule run dropped: bad run id", "automation", run.GetRule())
		default:
			if err := recordLocalRun(ctx, cfg, sess.device, run); err != nil {
				log.WarnContext(ctx, "record a local rule run", "automation", run.GetRule(), "err", err)
				ok = false
			}
		}
		if !ok {
			// Later runs wait for this one: acknowledgements are in order.
			break
		}
		acked = max(acked, run.GetSeq())
	}
	if acked == 0 {
		return
	}
	ack := &agentv1.HubMessage{Payload: &agentv1.HubMessage_LocalRunsAck{LocalRunsAck: &agentv1.LocalRunsAck{Seq: acked}}}
	if err := sess.sendMsg(ack); err != nil {
		log.WarnContext(ctx, "acknowledge the device's local rule runs", "err", err)
	}
}

// recordLocalRun writes the audit entries of run's steps, then the run in
// the run history, unless it is there already.
func recordLocalRun(ctx context.Context, cfg *LocalRulesConfig, device string, run *agentv1.LocalRun) error {
	now := cfg.Now()
	started := clampTime(run.GetStarted().AsTime(), now)
	finished := clampTime(run.GetFinished().AsTime(), now)
	if finished.Before(started) {
		finished = started
	}
	mark := localRan
	if !run.GetHubConnected() {
		mark = localRanHubsDown
	}
	steps := run.GetSteps()
	if len(steps) > maxLocalRunSteps {
		steps = steps[:maxLocalRunSteps]
	}
	results := []automation.StepResult{{
		ID: clip(run.GetTrigger()), Type: clip(run.GetTriggerType()), Status: "fired",
		Data:  map[string]any{"Target": clip(run.GetTarget()), "Error": clip(run.GetTriggerError())},
		RanOn: device, HubUnreachable: !run.GetHubConnected(),
	}}
	for _, st := range steps {
		action := policy.AutomationRestart
		if st.GetType() == "check" {
			action = policy.AutomationProbe
		}
		decision, result := policy.Allow, "ok"
		switch st.GetStatus() {
		case "ok":
		case "denied":
			decision, result = policy.Deny, clip(st.GetError())
		default:
			result = "error: " + clip(st.GetError())
		}
		detail, err := json.Marshal(map[string]any{
			"run": run.GetId(), "step": clip(st.GetId()), "trigger": clip(run.GetTrigger()),
			"local": mark, "device": device,
		})
		if err != nil {
			return err
		}
		if _, err := cfg.Audit.Append(ctx, store.AuditEntry{
			TS: finished, ActorKind: policy.ActorAutomation, ActorID: run.GetRule(), Action: string(action),
			Target: device, Decision: decision, Result: result, Detail: detail,
			// A run sent again after a lost acknowledgement lands once.
			Key: "local-run/" + device + "/" + run.GetId() + "/" + clip(st.GetId()),
		}); err != nil {
			return fmt.Errorf("audit: %w", err)
		}
		results = append(results, automation.StepResult{
			ID: clip(st.GetId()), Type: clip(st.GetType()), Status: clip(st.GetStatus()), Error: clip(st.GetError()),
		})
	}
	have, err := cfg.Runs.List(ctx, run.GetRule(), store.RunsKept)
	if err != nil && !errors.Is(err, store.ErrSchemaTooOld) {
		return fmt.Errorf("read the run history: %w", err)
	}
	if slices.ContainsFunc(have, func(r store.AutomationRun) bool { return r.ID == run.GetId() }) {
		return nil
	}
	b, err := json.Marshal(results)
	if err != nil {
		return err
	}
	status := run.GetStatus()
	if !slices.Contains([]string{automation.StatusSucceeded, automation.StatusFailed, automation.StatusDenied}, status) {
		status = automation.StatusFailed
	}
	return cfg.Runs.Record(ctx, store.AutomationRun{
		ID: run.GetId(), AutomationID: run.GetRule(), TriggerID: clip(run.GetTrigger()),
		StartedAt: started, FinishedAt: finished, Status: status, Error: clip(run.GetError()), Steps: b,
	})
}

// clampTime is t, unless it is in the future or too long ago: then now.
func clampTime(t, now time.Time) time.Time {
	if t.After(now) || t.Before(now.Add(-maxLocalRunAge)) {
		return now
	}
	return t
}

// clip bounds a text a device reported to maxLocalRunText bytes of valid
// UTF-8.
func clip(s string) string {
	if len(s) > maxLocalRunText {
		s = s[:maxLocalRunText]
	}
	return strings.ToValidUTF8(s, string(utf8.RuneError))
}
