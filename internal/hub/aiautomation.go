// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/gvart/hearth/internal/ai"
	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
)

const (
	// maxDraftBody bounds a draft's request: the text, JSON-escaped.
	maxDraftBody = 6*ai.MaxDraftRequest + 1<<10
	// draftAttempts bounds the completions of one draft: the first, and
	// one more with the validator's problems.
	draftAttempts = 2
	// draftDevices bounds the devices a draft names.
	draftDevices = 200
)

// aiAutomationRoutes registers the automation drafts, where both AI and the
// automation editor are served.
func (a *api) aiAutomationRoutes(mux *http.ServeMux) {
	if !a.configEditable() || !a.automations.Enabled() {
		return
	}
	mux.Handle("POST /api/v1/automations/draft", a.auth(a.draftAutomation))
}

// AutomationDraftRequestJSON asks for an automation, in the operator's words.
type AutomationDraftRequestJSON struct {
	Text string `json:"text"`
	// Preview gathers and redacts what would be sent, and sends nothing.
	Preview bool `json:"preview"`
}

// AutomationDraftJSON is a draft automation, never saved: the operator
// reviews it in the editor and saves it, as automation.apply, if at all.
type AutomationDraftJSON struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	BaseURL  string `json:"base_url"`
	// YAML is the draft file; empty for a preview.
	YAML string `json:"yaml"`
	// Valid says whether the hub's validator accepts YAML; Problems say
	// what it refuses when it does not.
	Valid    bool                 `json:"valid"`
	Problems []automation.Problem `json:"problems"`
	// Plan describes what a valid draft would do.
	Plan string `json:"plan,omitempty"`
	// Attempts is how many answers were asked for: a second one when the
	// first did not validate.
	Attempts int `json:"attempts"`
	// Sent is the last request as sent to the provider, after redaction.
	Sent         ai.Request `json:"sent"`
	SentBytes    int        `json:"sent_bytes"`
	Redactions   int        `json:"redactions"`
	Truncated    []string   `json:"truncated"`
	Preview      bool       `json:"preview"`
	InputTokens  int        `json:"input_tokens,omitempty"`
	OutputTokens int        `json:"output_tokens,omitempty"`
}

// draftAutomation asks the configured model for an automation file that
// does what the operator describes, grounded in the step types and the
// names of what the hub has, validates the answer with the hub's own
// validator and, if it is refused, asks once more with the problems. It is
// ai.automation.draft, a read, decided and audited before anything is
// gathered; the audit entry names the provider, the model and the sizes,
// never the text. Nothing is saved or run: the draft is returned.
func (a *api) draftAutomation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body AutomationDraftRequestJSON
	if !decodeJSON(w, r, maxDraftBody, &body, `{"text": "restart pihole-FTL on pi4 when DNS fails 3 times, then notify me", "preview": false}`) {
		return
	}
	body.Text = strings.TrimSpace(body.Text)
	if body.Text == "" || len(body.Text) > ai.MaxDraftRequest {
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("say what the automation should do, in at most %d characters", ai.MaxDraftRequest))
		return
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

	out := AutomationDraftJSON{
		Provider: cfg.Provider, Model: cfg.ModelName(), BaseURL: cfg.URL(), Preview: body.Preview,
		Problems: []automation.Problem{}, Truncated: []string{},
	}
	detail := map[string]any{"provider": cfg.Provider, "model": cfg.ModelName(), "host": hostOf(cfg.URL()), "preview": body.Preview}
	err = a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.AIAutomationDraft, Target: "automations",
		Detail: detail, RecordOutcome: true,
	}, func(ctx context.Context) error {
		p := ai.PrepareDraft(ai.Draft{Request: body.Text, Inventory: a.draftInventory(ctx)}, cfg.ContextBytes())
		p.Request.MaxTokens = cfg.MaxTokens
		req := p.Request
		out.Sent, out.SentBytes, out.Redactions = req, req.Size(), p.Redactions
		if p.Truncated != nil {
			out.Truncated = p.Truncated
		}
		// The outcome entry reads detail as it is when fn returns.
		detail["sent_bytes"], detail["redactions"] = out.SentBytes, out.Redactions
		if body.Preview {
			return nil
		}
		provider, err := ai.New(cfg)
		if err != nil {
			return err
		}
		sentBytes, answerBytes := 0, 0
		for out.Attempts < draftAttempts {
			if out.Attempts > 0 {
				var n int
				req, n = ai.RetryDraft(req, out.YAML, problemLines(out.Problems))
				out.Redactions += n
			}
			out.Attempts++
			resp, err := provider.Complete(ctx, req)
			if err != nil {
				return err
			}
			sentBytes += req.Size()
			out.Sent, out.SentBytes = req, sentBytes
			out.Model = resp.Model
			out.InputTokens += resp.InputTokens
			out.OutputTokens += resp.OutputTokens
			answerBytes += len(resp.Text)
			detail["attempts"], detail["sent_bytes"], detail["redactions"] = out.Attempts, out.SentBytes, out.Redactions
			detail["answer_bytes"], detail["input_tokens"], detail["output_tokens"] = answerBytes, out.InputTokens, out.OutputTokens
			out.YAML = ai.ExtractYAML(resp.Text)
			if strings.TrimSpace(out.YAML) == "" {
				return fmt.Errorf("draft an automation: %w", ai.ErrNoAnswer)
			}
			out.Valid, out.Plan, out.Problems = a.validateDraft(ctx, out.YAML)
			detail["valid"] = out.Valid
			if out.Valid {
				return nil
			}
		}
		return nil
	})
	if err != nil {
		a.writeExplainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// validateDraft checks a draft as a save from the web editor would, and
// describes what a valid one does. It writes nothing and asks policy
// nothing: the editor's dry run and save do.
func (a *api) validateDraft(ctx context.Context, draft string) (bool, string, []automation.Problem) {
	if len(draft) > maxAutomationBytes {
		return false, "", []automation.Problem{{Message: fmt.Sprintf("the file is over %d KiB", maxAutomationBytes>>10)}}
	}
	parsed, err := a.parseAutomation("", []byte(draft))
	if err != nil {
		return false, "", automation.Problems(err)
	}
	var plan bytes.Buffer
	if err := automation.Plan(&plan, parsed); err != nil {
		a.log.WarnContext(ctx, "plan a drafted automation", "err", err)
	}
	return true, plan.String(), []automation.Problem{}
}

// problemLines are the validator's problems as the model is told them.
func problemLines(problems []automation.Problem) []string {
	out := make([]string, 0, len(problems))
	for _, p := range problems {
		if p.Line > 0 && !strings.Contains(p.Message, fmt.Sprintf("line %d", p.Line)) {
			out = append(out, fmt.Sprintf("line %d: %s", p.Line, p.Message))
			continue
		}
		out = append(out, p.Message)
	}
	return out
}

// draftInventory names what a draft may refer to: the devices, with what
// their agents let automations restart, run and check; the notification
// channels; the Kubernetes clusters; the plugins and their commands; and
// the automation ids already taken. Names only: no facts, metrics or
// secrets. What cannot be read is left out.
func (a *api) draftInventory(ctx context.Context) []ai.Section {
	var devices strings.Builder
	if list, err := a.store.Devices().List(ctx); err != nil {
		a.log.WarnContext(ctx, "draft an automation: list devices", "err", err)
	} else {
		for i, d := range list {
			if i == draftDevices {
				fmt.Fprintf(&devices, "... and %d more\n", len(list)-draftDevices)
				break
			}
			devices.WriteString(d.Name)
			var notes []string
			if d.Hostname != "" && d.Hostname != d.Name {
				notes = append(notes, "hostname "+d.Hostname)
			}
			if d.OS != "" {
				notes = append(notes, d.OS)
			}
			if d.Status != "" {
				notes = append(notes, d.Status)
			}
			var f Facts
			if len(d.Facts) > 0 && json.Unmarshal(d.Facts, &f) == nil && f.Ceiling != nil {
				if len(f.Ceiling.Restart) > 0 {
					notes = append(notes, "may restart "+strings.Join(f.Ceiling.Restart, ", "))
				}
				if len(f.Ceiling.Exec) > 0 {
					notes = append(notes, "may run "+strings.Join(f.Ceiling.Exec, ", "))
				}
				if f.Ceiling.Probe {
					notes = append(notes, "may run checks (from)")
				}
			}
			if len(notes) > 0 {
				fmt.Fprintf(&devices, " (%s)", strings.Join(notes, "; "))
			}
			devices.WriteByte('\n')
		}
	}

	var channels strings.Builder
	for _, c := range a.notify.Channels() {
		fmt.Fprintf(&channels, "%s (%s)\n", c.Name, c.Type)
	}

	var clusters strings.Builder
	if a.kube != nil {
		for _, c := range a.kube.Clusters() {
			if !c.Removed {
				fmt.Fprintf(&clusters, "%s\n", c.Name)
			}
		}
	}

	var plugins strings.Builder
	if a.plugins != nil {
		for _, p := range a.plugins.Plugins() {
			cmds := make([]string, 0, len(p.Commands))
			for _, c := range p.Commands {
				cmds = append(cmds, fmt.Sprintf("%s (%s)", c.Name, c.Class))
			}
			fmt.Fprintf(&plugins, "%s: %s\n", p.Name, strings.Join(cmds, ", "))
		}
	}

	var ids []string
	if files, err := a.automations.List(ctx); err != nil {
		a.log.WarnContext(ctx, "draft an automation: list automations", "err", err)
	} else {
		for _, f := range files {
			if f.ID != "" {
				ids = append(ids, f.ID)
			}
		}
	}
	slices.Sort(ids)

	return []ai.Section{
		{ID: "devices", Title: "Devices (name, then what is known)", Body: devices.String()},
		{ID: "channels", Title: "Notification channels (name and type)", Body: channels.String()},
		{ID: "clusters", Title: "Kubernetes clusters", Body: clusters.String()},
		{ID: "plugins", Title: "Plugins and their commands (with their policy class)", Body: plugins.String()},
		{ID: "automations", Title: "Existing automation ids (do not reuse one)", Body: strings.Join(ids, "\n")},
	}
}
