// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/ai"
	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/hubconfig"
	"github.com/gvart/hearth/internal/metrics"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// Limits of an explanation's evidence.
const (
	maxExplainBody   = 8 << 10
	maxExplainLogs   = 3
	explainLogTail   = 200
	explainAuditRows = 30
	explainMetrics   = 6 * time.Hour
	// explainLogWait bounds how long a log tail is read: the agent sends
	// the tail at once, then follows the source.
	explainLogWait  = 3 * time.Second
	explainLogQuiet = 500 * time.Millisecond
)

// aiRoutes registers the AI API, with the store's configuration documents:
// ai.yaml is one, sealed. Without documents AI is not served, and the web UI
// reads the 404 as off.
func (a *api) aiRoutes(mux *http.ServeMux) {
	if !a.configEditable() {
		return
	}
	mux.Handle("GET /api/v1/ai", a.auth(a.getAIConfig))
	mux.Handle("PUT /api/v1/ai/config", a.auth(a.putAIConfig))
	mux.Handle("POST /api/v1/devices/{id}/explain", a.auth(a.explainDevice))
}

// AIConfigJSON is ai.yaml as the web UI and the CLI see it: everything but
// the API key, of which only whether one is set.
type AIConfigJSON struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	// BaseURL and Model are the ones in effect, defaults filled in.
	BaseURL         string `json:"base_url"`
	Model           string `json:"model"`
	APIKeySet       bool   `json:"api_key_set"`
	MaxTokens       int    `json:"max_tokens"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	MaxContextBytes int    `json:"max_context_bytes"`
	// Revision is the stored document's, for an edit to name.
	Revision string `json:"revision"`
}

func aiConfigJSON(c ai.Config, revision string) AIConfigJSON {
	return AIConfigJSON{
		Enabled: c.Enabled(), Provider: c.Provider, BaseURL: c.URL(), Model: c.ModelName(), APIKeySet: c.APIKey != "",
		MaxTokens: c.MaxTokens, TimeoutSeconds: c.TimeoutSeconds, MaxContextBytes: c.MaxContextBytes, Revision: revision,
	}
}

// storedAI is the stored ai.yaml, parsed, and its revision; off without one.
func storedAI(current []hubconfig.Doc) (ai.Config, string, error) {
	doc, _ := docOf(current, store.ConfigAI, hubconfig.AIFile)
	c, err := ai.ParseConfig(doc.Content)
	if err != nil {
		return ai.Config{}, "", configInvalid{errors.New(hubconfig.AIFile + ": the stored file does not load: fix it with `hearth config import`")}
	}
	return c, automation.Revision(doc.Content), nil
}

func (a *api) aiConfig(ctx context.Context) (ai.Config, string, error) {
	current, err := a.loadConfig(ctx)
	if err != nil {
		return ai.Config{}, "", err
	}
	return storedAI(current)
}

func (a *api) getAIConfig(w http.ResponseWriter, r *http.Request) {
	c, rev, err := a.aiConfig(r.Context())
	if err != nil {
		a.writeConfigError(w, r, "read the AI settings", err)
		return
	}
	writeJSON(w, http.StatusOK, aiConfigJSON(c, rev))
}

// aiConfigBody is an edit of ai.yaml. An empty provider turns AI off. An
// empty api_key keeps the stored one, but only for the same provider and
// address: a key is never sent anywhere but where it was entered for.
type aiConfigBody struct {
	Provider        string `json:"provider"`
	BaseURL         string `json:"base_url"`
	Model           string `json:"model"`
	APIKey          string `json:"api_key"`
	ClearAPIKey     bool   `json:"clear_api_key"`
	MaxTokens       int    `json:"max_tokens"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	MaxContextBytes int    `json:"max_context_bytes"`
	// Revision is the revision the edit started from.
	Revision string `json:"revision"`
}

// putAIConfig writes ai.yaml: sensitive, as config.import by the web actor
// with the password again, since it decides where the hub sends what it
// knows. The file is sealed before it is stored; the key is never logged,
// audited or served.
func (a *api) putAIConfig(w http.ResponseWriter, r *http.Request) {
	var body aiConfigBody
	if !decodeJSON(w, r, maxTokenBody, &body, `{"provider": "openai|anthropic|", "base_url": "...", "model": "...", "api_key": "..."}`) {
		return
	}
	id := store.ConfigDocID(store.ConfigAI, hubconfig.AIFile)
	next := ai.Config{
		Provider: body.Provider, BaseURL: strings.TrimSpace(body.BaseURL), Model: strings.TrimSpace(body.Model),
		APIKey: strings.TrimSpace(body.APIKey), MaxTokens: body.MaxTokens, TimeoutSeconds: body.TimeoutSeconds,
		MaxContextBytes: body.MaxContextBytes,
	}
	keyChanged := next.APIKey != "" || body.ClearAPIKey
	err := a.writeConfig(r, configWrite{
		build: func(current []hubconfig.Doc) ([]hubconfig.Doc, error) {
			stored, rev, err := storedAI(current)
			if err != nil {
				return nil, err
			}
			if body.Revision != rev {
				return nil, errConfigChanged
			}
			if next.APIKey == "" && !body.ClearAPIKey && stored.Provider == next.Provider && stored.URL() == next.URL() {
				next.APIKey = stored.APIKey
			}
			if !next.Enabled() {
				next = ai.Config{}
			}
			b, err := next.Marshal()
			if err != nil {
				return nil, err
			}
			return []hubconfig.Doc{{Kind: store.ConfigAI, Name: hubconfig.AIFile, Content: b}}, nil
		},
		sensitive: true, target: id,
		detail: map[string]any{
			"documents": []string{id}, "provider": next.Provider, "model": next.ModelName(), "host": hostOf(next.URL()),
			"api_key_changed": keyChanged,
		},
	})
	if err != nil {
		a.writeConfigError(w, r, "save the AI settings", err)
		return
	}
	c, rev, err := a.aiConfig(r.Context())
	if err != nil {
		a.writeConfigError(w, r, "read the AI settings", err)
		return
	}
	writeJSON(w, http.StatusOK, aiConfigJSON(c, rev))
}

// hostOf is the host of a base URL, for the audit log.
func hostOf(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return u.Host
}

// ExplainRequestJSON asks why a device misbehaves.
type ExplainRequestJSON struct {
	// Question is the operator's; empty asks whether anything is wrong.
	Question string `json:"question"`
	// Logs are log sources (manager:name) whose tail to include, each read
	// as its own device.logs action.
	Logs []string `json:"logs"`
	// Preview gathers and redacts the evidence and sends nothing.
	Preview bool `json:"preview"`
}

// ExplainJSON is an explanation, with exactly what was sent for it.
type ExplainJSON struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	// BaseURL is where it was sent.
	BaseURL string `json:"base_url"`
	// Answer is the model's text, shown as plain text; empty for a preview.
	Answer string `json:"answer"`
	// Sent is the request as sent to the provider, after redaction.
	Sent       ai.Request `json:"sent"`
	SentBytes  int        `json:"sent_bytes"`
	Redactions int        `json:"redactions"`
	// Truncated names the evidence sections cut to fit.
	Truncated []string `json:"truncated"`
	// Notes say what could not be gathered, such as a log the agent would
	// not stream.
	Notes        []string `json:"notes"`
	Preview      bool     `json:"preview"`
	InputTokens  int      `json:"input_tokens,omitempty"`
	OutputTokens int      `json:"output_tokens,omitempty"`
}

// errAIOff refuses an explanation while AI is off.
var errAIOff = errors.New("AI is off: set up a provider first")

// explainDevice gathers what the hub knows of a device, redacts it, and asks
// the configured model what is wrong: ai.explain, a read, decided and
// audited before anything is gathered. The audit entry names the provider,
// the model and the sizes, never the question, the evidence or the answer.
// The model never acts: its answer is text.
func (a *api) explainDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body ExplainRequestJSON
	if !decodeJSON(w, r, maxExplainBody, &body, `{"question": "...", "logs": ["systemd:nginx.service"], "preview": false}`) {
		return
	}
	body.Logs = slices.Compact(slices.Sorted(slices.Values(body.Logs)))
	if len(body.Logs) > maxExplainLogs {
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("at most %d log sources", maxExplainLogs))
		return
	}
	for _, src := range body.Logs {
		if m, n, ok := strings.Cut(src, ":"); !ok || m == "" || n == "" {
			writeError(w, http.StatusBadRequest, "bad_request", "a log source is manager:name, such as systemd:nginx.service")
			return
		}
	}
	cfg, _, err := a.aiConfig(ctx)
	if err != nil {
		a.writeConfigError(w, r, "read the AI settings", err)
		return
	}
	if !cfg.Enabled() {
		writeError(w, http.StatusConflict, "ai_off", errAIOff.Error())
		return
	}
	d, err := a.store.Devices().Get(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such device")
		return
	}
	if err != nil {
		a.writeActionError(w, r, "explain", err)
		return
	}

	out := ExplainJSON{Provider: cfg.Provider, Model: cfg.ModelName(), BaseURL: cfg.URL(), Preview: body.Preview}
	detail := map[string]any{"provider": cfg.Provider, "model": cfg.ModelName(), "host": hostOf(cfg.URL()), "preview": body.Preview}
	if len(body.Logs) > 0 {
		detail["logs"] = body.Logs
	}
	err = a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.AIExplain, Target: d.ID,
		Detail: detail, RecordOutcome: true,
	}, func(ctx context.Context) error {
		sections, notes := a.explainEvidence(ctx, r, d, body.Logs)
		p := ai.PrepareExplain(ai.Explain{Subject: deviceSubject(d), Question: body.Question, Sections: sections}, cfg.ContextBytes())
		p.Request.MaxTokens = cfg.MaxTokens
		out.Sent, out.SentBytes, out.Redactions, out.Notes = p.Request, p.Request.Size(), p.Redactions, notes
		out.Truncated = p.Truncated
		// The outcome entry reads detail as it is when fn returns.
		detail["sent_bytes"], detail["redactions"] = out.SentBytes, out.Redactions
		if body.Preview {
			return nil
		}
		provider, err := ai.New(cfg)
		if err != nil {
			return err
		}
		resp, err := provider.Complete(ctx, p.Request)
		if err != nil {
			return err
		}
		out.Answer, out.Model, out.InputTokens, out.OutputTokens = resp.Text, resp.Model, resp.InputTokens, resp.OutputTokens
		detail["answer_bytes"], detail["input_tokens"], detail["output_tokens"] = len(resp.Text), resp.InputTokens, resp.OutputTokens
		return nil
	})
	if err != nil {
		a.writeExplainError(w, r, err)
		return
	}
	if out.Notes == nil {
		out.Notes = []string{}
	}
	if out.Truncated == nil {
		out.Truncated = []string{}
	}
	writeJSON(w, http.StatusOK, out)
}

// writeExplainError answers a failed explanation. A provider's error names
// what failed, never the key.
func (a *api) writeExplainError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ai.ErrAuth):
		writeError(w, http.StatusBadGateway, "ai_auth", err.Error())
	case errors.Is(err, ai.ErrNotFound):
		writeError(w, http.StatusBadGateway, "ai_not_found", err.Error())
	case errors.Is(err, ai.ErrRateLimited):
		writeError(w, http.StatusBadGateway, "ai_rate_limited", err.Error())
	case errors.Is(err, ai.ErrUnavailable):
		writeError(w, http.StatusBadGateway, "ai_unavailable", err.Error())
	case errors.Is(err, ai.ErrBadRequest), errors.Is(err, ai.ErrNoAnswer):
		writeError(w, http.StatusBadGateway, "ai_error", err.Error())
	case errors.Is(err, ai.ErrTimeout):
		writeError(w, http.StatusGatewayTimeout, "ai_timeout", "the model did not answer in time: raise timeout_seconds, or use a smaller model")
	default:
		a.writeActionError(w, r, "explain", err)
	}
}

func deviceSubject(d store.Device) string {
	s := "device " + d.Name
	if d.Hostname != "" && d.Hostname != d.Name {
		s += " (" + d.Hostname + ")"
	}
	return s
}

// explainEvidence gathers the evidence about d, most useful first, and notes
// on what could not be had. Nothing here fails the explanation.
func (a *api) explainEvidence(ctx context.Context, r *http.Request, d store.Device, logs []string) ([]ai.Section, []string) {
	var notes []string
	sections := []ai.Section{{ID: "device", Title: "Device facts and status", Body: a.deviceEvidence(d)}}
	if body, note := a.metricsEvidence(ctx, d.ID); note != "" {
		notes = append(notes, note)
	} else {
		sections = append(sections, ai.Section{ID: "metrics", Title: "Metrics over the last 6 hours", Body: body})
	}
	if body, err := a.auditEvidence(ctx, d); err != nil {
		notes = append(notes, "the audit log could not be read")
	} else {
		sections = append(sections, ai.Section{ID: "audit", Title: "Recent audit log entries about it, newest first", Body: body})
	}
	for _, src := range logs {
		body, err := a.logEvidence(ctx, r, d.ID, src)
		if err != nil {
			notes = append(notes, fmt.Sprintf("log %s left out: %s", src, logNote(err)))
			continue
		}
		sections = append(sections, ai.Section{ID: "log:" + src, Title: "Last lines of the log " + src, Body: body, KeepTail: true})
	}
	return sections, notes
}

func (a *api) deviceEvidence(d store.Device) string {
	now := a.now()
	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%s: %s\n", k, v)
		}
	}
	line("name", d.Name)
	line("id", d.ID)
	line("hostname", d.Hostname)
	line("status", d.Status)
	if !d.LastSeen.IsZero() {
		line("last seen", fmt.Sprintf("%s (%s ago)", d.LastSeen.UTC().Format(time.RFC3339), now.Sub(d.LastSeen).Round(time.Second)))
	}
	if !d.BootTime.IsZero() {
		line("booted", fmt.Sprintf("%s (up %s)", d.BootTime.UTC().Format(time.RFC3339), now.Sub(d.BootTime).Round(time.Minute)))
	}
	if !d.FirstSeen.IsZero() {
		line("enrolled", d.FirstSeen.UTC().Format(time.RFC3339))
	}
	keys := slices.Sorted(func(yield func(string) bool) {
		for k := range d.Labels {
			if !yield(k) {
				return
			}
		}
	})
	for _, k := range keys {
		line("label "+k, d.Labels[k])
	}
	var f Facts
	if len(d.Facts) > 0 && json.Unmarshal(d.Facts, &f) == nil {
		line("os", strings.TrimSpace(f.OS+" "+f.Arch))
		line("kernel", f.Kernel)
		line("agent", f.AgentVersion)
		if f.RolledBackFrom != "" {
			line("agent upgrade rolled back from", f.RolledBackFrom)
		}
		if f.CPUCores > 0 {
			line("cpu", fmt.Sprintf("%s, %d cores", f.CPUModel, f.CPUCores))
		}
		if f.MemTotalBytes > 0 {
			line("memory", fmt.Sprintf("%.1f GiB", float64(f.MemTotalBytes)/(1<<30)))
		}
		for _, disk := range f.Disks {
			use := ""
			if disk.UsedBytes > 0 && disk.TotalBytes > 0 {
				use = fmt.Sprintf(", %.0f%% used", 100*float64(disk.UsedBytes)/float64(disk.TotalBytes))
			}
			line("disk "+disk.Mountpoint, fmt.Sprintf("%s %s, %.1f GiB%s", disk.Device, disk.FSType, float64(disk.TotalBytes)/(1<<30), use))
		}
		for _, i := range f.Interfaces {
			line("interface "+i.Name, strings.Join(i.IPs, " "))
		}
	}
	return b.String()
}

// metricsEvidence summarises each known metric of the last hours: newest,
// lowest, average and highest. A note says why there is none.
func (a *api) metricsEvidence(ctx context.Context, device string) (string, string) {
	if a.metrics == nil {
		return "", "the hub keeps no metrics"
	}
	end := a.now()
	names := make([]string, 0, len(metrics.Known))
	for _, s := range metrics.Known {
		names = append(names, s.Key)
	}
	series, err := a.metrics.Query(ctx, device, names, end.Add(-explainMetrics), end, 10*time.Minute)
	if err != nil {
		return "", "the metrics could not be read"
	}
	var b strings.Builder
	for _, s := range metrics.Known {
		pts := series[s.Key]
		if len(pts) == 0 {
			continue
		}
		lo, hi, sum := pts[0], pts[0], 0.0
		for _, p := range pts {
			sum += p.V
			if p.V < lo.V {
				lo = p
			}
			if p.V > hi.V {
				hi = p
			}
		}
		last := pts[len(pts)-1]
		fmt.Fprintf(&b, "%s (%s): now %.1f (at %s), min %.1f, avg %.1f, max %.1f at %s\n", s.Name, s.Unit,
			last.V, last.T.UTC().Format("15:04"), lo.V, sum/float64(len(pts)), hi.V, hi.T.UTC().Format("15:04"))
	}
	if b.Len() == 0 {
		return "", "no metrics from this device in the last 6 hours"
	}
	return b.String(), ""
}

// auditEvidence lists the latest audit entries whose target is the device,
// by id, name or hostname (automations name devices), leaving out the
// explanations themselves.
func (a *api) auditEvidence(ctx context.Context, d store.Device) (string, error) {
	targets := slices.Compact(slices.Sorted(slices.Values(slices.DeleteFunc([]string{d.ID, d.Name, d.Hostname}, func(s string) bool { return s == "" }))))
	entries, err := a.store.Audit().Query(ctx, store.AuditFilter{Targets: targets}, explainAuditRows*2)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	n := 0
	for _, e := range entries {
		if e.Action == string(policy.AIExplain) || n == explainAuditRows {
			continue
		}
		n++
		fmt.Fprintf(&b, "%s %s %s/%s %s: %s\n", e.TS.UTC().Format(time.RFC3339), e.Action, e.ActorKind, e.ActorID, e.Decision, e.Result)
	}
	if n == 0 {
		return "(none)", nil
	}
	return b.String(), nil
}

// logEvidence reads the tail of a log source of the device: device.logs of
// its own, as the log viewer opens it, with the agent's ceiling checked
// first.
func (a *api) logEvidence(ctx context.Context, r *http.Request, device, source string) (string, error) {
	if a.agents == nil {
		return "", ErrAgentNotConnected
	}
	manager, name, _ := strings.Cut(source, ":")
	src := &agentv1.LogSource{Manager: manager, Name: name}
	var stream *LogStream
	err := a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.DeviceLogs, Target: device,
		Detail:   map[string]any{"source": source, "tail": explainLogTail, "for": string(policy.AIExplain)},
		Precheck: func(ctx context.Context) error { return a.agents.CheckLogs(ctx, device, src) },
	}, func(ctx context.Context) error {
		var err error
		stream, err = a.agents.Logs(ctx, device, src, explainLogTail)
		return err
	})
	if stream != nil {
		defer stream.Close()
	}
	if err != nil {
		return "", err
	}
	var b strings.Builder
	deadline := time.NewTimer(explainLogWait)
	defer deadline.Stop()
	var quiet <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline.C:
			return b.String(), nil
		case <-quiet:
			return b.String(), nil
		case <-stream.Disconnected():
			return b.String(), nil
		case <-stream.Ready():
			for m := stream.Take(); m != nil; m = stream.Take() {
				for _, l := range m.GetLines() {
					b.WriteString(l.GetText())
					b.WriteByte('\n')
				}
				if m.GetEnd() {
					if e := m.GetError(); e != "" && b.Len() == 0 {
						return "", errors.New(e)
					}
					return b.String(), nil
				}
			}
			// The tail came: whatever follows within a moment is new.
			quiet = time.After(explainLogQuiet)
		}
	}
}

// logNote says why a log was left out, without internals.
func logNote(err error) string {
	switch {
	case errors.Is(err, ErrAgentNotConnected):
		return "the device's agent is not connected to this hub"
	case errors.Is(err, policy.ErrDenied):
		return err.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return "it did not answer in time"
	}
	return "it could not be read"
}
