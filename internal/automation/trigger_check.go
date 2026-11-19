// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/probe"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// defaultCheckEvery is how often a synthetic check runs.
const defaultCheckEvery = 10 * time.Second

// maxProbeTimeout is the longest timeout a check from a device may set;
// agents cap it the same way.
const maxProbeTimeout = time.Minute

// probeGrace is how long the hub waits past a check's timeout for the
// agent's answer before giving up on it.
const probeGrace = 5 * time.Second

// Probers run checks from devices through their agents: *hub.Agents. device
// is a device id, name or hostname.
type Probers interface {
	// CheckProbe reports whether a probe would be sent to the agent of
	// device: an error wrapping policy.ErrBeyondCeiling when its ceiling
	// does not allow probes.
	CheckProbe(ctx context.Context, device string) error
	// Probe runs req on the agent of device and returns its result.
	Probe(ctx context.Context, device string, req *agentv1.ProbeRequest) (*agentv1.ProbeResult, error)
}

// checkTrigger fires when a synthetic check, run from the hub or from a
// device, has failed for a duration. It fires once per outage: again only
// after the check passed. A check from a device that cannot run (its agent
// is offline, too old, or does not allow probes) changes nothing: it neither
// fires nor ends an outage.
type checkTrigger struct {
	what string // for Describe: "HTTP GET http://nas.lan" ...
	// target is what is checked, for actions: the URL (password redacted),
	// name or address.
	target string
	timing pollTiming
	// req is the check; it carries the URL unredacted.
	req *agentv1.ProbeRequest
	// from is the device the check runs from; empty for the hub.
	from string
	// kubeNode, for a runbook's kube_node check, reads a Node instead of
	// sending req.
	kubeNode *kubeNodeCheck
	probers  Probers
	policy   Policy
	clock    Clock
	log      *slog.Logger
}

func (t *checkTrigger) Describe() string {
	where := "the hub"
	if t.from != "" {
		where = "device " + t.from
	}
	return fmt.Sprintf("fires when %s fails%s (checked every %s from %s)", t.what, forText(t.timing.For), t.timing.Every, where)
}

func (t *checkTrigger) Watch(ctx context.Context, fire FireFunc) error {
	if t.from != "" {
		if err := t.decide(ctx); err != nil {
			return err
		}
	}
	var lastErr string // why the last check could not run; logged once
	return poller{clock: t.clock, every: t.timing.Every, hold: t.timing.For, bad: func(ctx context.Context) (map[string]any, pollState) {
		ran, err := t.run(ctx)
		switch {
		case ctx.Err() != nil:
		case !ran:
			if err.Error() != lastErr {
				t.log.WarnContext(ctx, "check cannot run from its device", "check", t.what, "device", t.from, "err", err)
				lastErr = err.Error()
			}
			return nil, stateUnknown
		case lastErr != "":
			t.log.InfoContext(ctx, "check runs from its device again", "check", t.what, "device", t.from)
			lastErr = ""
		}
		if err == nil {
			return nil, stateGood
		}
		if ctx.Err() == nil {
			t.log.DebugContext(ctx, "check failed", "check", t.what, "err", err)
		}
		return t.data(err.Error()), stateBad
	}}.watch(ctx, fire)
}

// decide asks policy, once, whether the automation may check from the
// device; the decision is audited, and the checks run under it until the
// trigger stops. A device whose reported ceiling does not allow probes is
// denied.
func (t *checkTrigger) decide(ctx context.Context) error {
	if t.probers == nil || t.policy == nil {
		return errors.New("this hub does not run checks from devices")
	}
	of := triggerFrom(ctx)
	return t.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorAutomation,
		ActorID:   of.automation,
		Action:    policy.AutomationProbe,
		Target:    t.from,
		Detail:    map[string]any{"trigger": of.trigger, "check": t.what},
		Precheck:  func(ctx context.Context) error { return t.probers.CheckProbe(ctx, t.from) },
	}, func(context.Context) error { return nil })
}

// run runs one check: the error says why it failed, nil when it passed. ran
// is false when a check from a device could not run at all; the error then
// says why.
func (t *checkTrigger) run(ctx context.Context) (ran bool, err error) {
	if t.from == "" {
		pctx, cancel := context.WithTimeout(ctx, t.timing.Timeout)
		defer cancel()
		return true, probe.Run(pctx, t.req)
	}
	req := proto.CloneOf(t.req)
	req.Timeout = durationpb.New(t.timing.Timeout)
	pctx, cancel := context.WithTimeout(ctx, t.timing.Timeout+probeGrace)
	defer cancel()
	res, err := t.probers.Probe(pctx, t.from, req)
	switch {
	case err != nil:
		return false, err
	case res.GetDenied():
		return false, fmt.Errorf("device %s: %w", t.from, policy.ErrBeyondCeiling)
	case res.GetError() != "":
		return true, errors.New(res.GetError())
	}
	return true, nil
}

func (t *checkTrigger) Sample() map[string]any { return t.data("connection refused") }

// data is what a failed check tells actions.
func (t *checkTrigger) data(err string) map[string]any {
	return map[string]any{"Target": t.target, "Error": err}
}

// newCheck builds a check trigger from the fields every check has.
func newCheck(deps TriggerDeps, from string, every, hold, timeout time.Duration) (*checkTrigger, error) {
	t := pollTiming{Every: every, For: hold, Timeout: timeout}
	if err := t.check(defaultCheckEvery); err != nil {
		return nil, err
	}
	if from = strings.TrimSpace(from); from != "" && t.Timeout > maxProbeTimeout {
		return nil, fmt.Errorf("timeout must be at most %s for a check from a device", maxProbeTimeout)
	}
	return &checkTrigger{timing: t, from: from, probers: deps.Probers, policy: deps.Policy, clock: deps.Clock, log: deps.Log}, nil
}

func buildHTTPCheck(p Params, deps TriggerDeps) (Trigger, error) {
	var cfg struct {
		URL     string        `yaml:"url"`
		Status  int           `yaml:"status"`
		From    string        `yaml:"from"`
		Every   time.Duration `yaml:"every"`
		For     time.Duration `yaml:"for"`
		Timeout time.Duration `yaml:"timeout"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("url must be http(s)://host[:port][/path]")
	}
	if cfg.Status != 0 && (cfg.Status < 100 || cfg.Status > 599) {
		return nil, fmt.Errorf("status %d is not an HTTP status", cfg.Status)
	}
	t, err := newCheck(deps, cfg.From, cfg.Every, cfg.For, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	want := "a 2xx or 3xx status"
	if cfg.Status != 0 {
		want = fmt.Sprintf("status %d", cfg.Status)
	}
	t.what = fmt.Sprintf("HTTP GET %s (expecting %s)", redactURL(u), want)
	t.target = redactURL(u)
	t.req = &agentv1.ProbeRequest{Probe: &agentv1.ProbeRequest_Http{
		Http: &agentv1.HTTPProbe{Url: cfg.URL, Status: int32(cfg.Status)}, //nolint:gosec // checked above: 100-599
	}}
	return t, nil
}

// redactURL is u with its password and query values replaced by REDACTED,
// as it may be shown: in plans, logs, run history and action templates.
// Health-check URLs often carry a token in either.
func redactURL(u *url.URL) string {
	r := *u
	// A part of the query that does not parse is dropped, never shown.
	q := r.Query()
	for _, vs := range q {
		for i := range vs {
			vs[i] = "REDACTED"
		}
	}
	r.RawQuery, r.Fragment, r.RawFragment = q.Encode(), "", ""
	return r.Redacted()
}

func buildTCPCheck(p Params, deps TriggerDeps) (Trigger, error) {
	var cfg struct {
		Address string        `yaml:"address"`
		From    string        `yaml:"from"`
		Every   time.Duration `yaml:"every"`
		For     time.Duration `yaml:"for"`
		Timeout time.Duration `yaml:"timeout"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	if host, port, err := net.SplitHostPort(cfg.Address); err != nil || host == "" || port == "" {
		return nil, errors.New("address must be host:port")
	}
	t, err := newCheck(deps, cfg.From, cfg.Every, cfg.For, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	t.what = "TCP connect to " + cfg.Address
	t.target = cfg.Address
	t.req = &agentv1.ProbeRequest{Probe: &agentv1.ProbeRequest_Tcp{Tcp: &agentv1.TCPProbe{Address: cfg.Address}}}
	return t, nil
}

func buildDNSCheck(p Params, deps TriggerDeps) (Trigger, error) {
	var cfg struct {
		Name    string        `yaml:"name"`
		Server  string        `yaml:"server"`
		From    string        `yaml:"from"`
		Every   time.Duration `yaml:"every"`
		For     time.Duration `yaml:"for"`
		Timeout time.Duration `yaml:"timeout"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	if _, err := probe.DNSName(cfg.Name); err != nil {
		return nil, err
	}
	server := cfg.Server
	if server == "" {
		return nil, errors.New("server is required: the DNS server to ask, host or host:port")
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(strings.Trim(server, "[]"), "53")
	}
	t, err := newCheck(deps, cfg.From, cfg.Every, cfg.For, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	t.what = fmt.Sprintf("DNS lookup of %s A at %s", cfg.Name, server)
	t.target = cfg.Name
	t.req = &agentv1.ProbeRequest{Probe: &agentv1.ProbeRequest_Dns{Dns: &agentv1.DNSProbe{Name: cfg.Name, Server: server}}}
	return t, nil
}
