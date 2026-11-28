// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/gvart/hearth/internal/ai"
	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/hubconfig"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// maxRunbookDraftBody bounds a runbook draft's request: the notes,
// JSON-escaped.
const maxRunbookDraftBody = 6*ai.MaxRunbookNotes + 1<<10

// aiRunbookRoutes registers the runbook drafts from recorded terminal
// sessions, where AI, the runbook editor and terminals are served. A draft
// is served by the hub holding the device's stream, which holds its
// recordings.
func (a *api) aiRunbookRoutes(mux *http.ServeMux) {
	if a.runbooks == nil || a.agents == nil {
		return
	}
	mux.Handle("POST /api/v1/devices/{id}/recordings/{rec}/runbook", a.auth(a.proxyStream(a.draftRunbook)))
}

// RunbookDraftRequestJSON asks for a runbook from a recorded session.
type RunbookDraftRequestJSON struct {
	// Notes are the operator's own words on what the session did.
	Notes string `json:"notes"`
	// Preview gathers and redacts what would be sent, sends nothing and
	// keeps the recording.
	Preview bool `json:"preview"`
}

// RunbookDraftJSON is a draft runbook, never saved: the operator reviews it
// in the editor and saves it, as config.import, if at all.
type RunbookDraftJSON struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	BaseURL  string `json:"base_url"`
	// YAML is the draft file, and File the file it would be saved as;
	// empty for a preview.
	YAML string `json:"yaml"`
	File string `json:"file"`
	// Valid says whether the hub's validator accepts YAML; Problems say
	// what it refuses when it does not, and Plan what a valid one would do.
	Valid    bool                    `json:"valid"`
	Problems []automation.Problem    `json:"problems"`
	Plan     *automation.RunbookPlan `json:"plan,omitempty"`
	// Attempts is how many answers were asked for: a second one when the
	// first did not validate.
	Attempts int `json:"attempts"`
	// Sent is the last request as sent to the provider, after redaction.
	Sent       ai.Request `json:"sent"`
	SentBytes  int        `json:"sent_bytes"`
	Redactions int        `json:"redactions"`
	Truncated  []string   `json:"truncated"`
	Preview    bool       `json:"preview"`
	// Discarded says the recording was deleted, as it is once the model
	// answered.
	Discarded    bool `json:"discarded"`
	InputTokens  int  `json:"input_tokens,omitempty"`
	OutputTokens int  `json:"output_tokens,omitempty"`
}

// draftRunbook asks the configured model for a runbook that does what a
// recorded terminal session did, grounded in the step types and the names
// of what the hub has, validates the answer as the runbook editor's save
// does and, if it is refused, asks once more with the problems. It is
// ai.runbook.draft, a read, decided and audited before the transcript is
// read; the audit entry names the provider, the model and the sizes, never
// the text. Once a draft is returned, the recording is deleted. Nothing is
// saved or run: the draft is returned.
func (a *api) draftRunbook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body RunbookDraftRequestJSON
	if !decodeJSON(w, r, maxRunbookDraftBody, &body, `{"notes": "added a k3s node", "preview": false}`) {
		return
	}
	if len(body.Notes) > ai.MaxRunbookNotes {
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("notes may be at most %d characters", ai.MaxRunbookNotes))
		return
	}
	dev, err := a.store.Devices().Get(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such device")
		return
	}
	if err != nil {
		a.writeActionError(w, r, "get the device", err)
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
	id := r.PathValue("rec")
	rec, ok := a.recordings.get(dev.ID, id)
	if !ok {
		writeNoRecording(w)
		return
	}
	if rec.ended.IsZero() {
		writeError(w, http.StatusConflict, "recording", "the session is still being recorded: close its terminal first")
		return
	}

	out := RunbookDraftJSON{
		Provider: cfg.Provider, Model: cfg.ModelName(), BaseURL: cfg.URL(), Preview: body.Preview,
		Problems: []automation.Problem{}, Truncated: []string{},
	}
	detail := map[string]any{
		"provider": cfg.Provider, "model": cfg.ModelName(), "host": hostOf(cfg.URL()), "preview": body.Preview,
		"device": dev.Name, "recording": id, "recorded_bytes": len(rec.out),
	}
	err = a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.AIRunbookDraft, Target: dev.ID,
		Detail: detail, RecordOutcome: true,
	}, func(ctx context.Context) error {
		p := ai.PrepareRunbook(ai.RunbookDraft{
			Device: dev.Name, Notes: body.Notes, Transcript: screenText(rec.out), Inventory: a.runbookInventory(ctx),
		}, cfg.ContextBytes())
		p.Request.MaxTokens = cfg.MaxTokens
		req := p.Request
		out.Sent, out.SentBytes, out.Redactions = req, req.Size(), p.Redactions
		if p.Truncated != nil {
			out.Truncated = p.Truncated
		}
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
				return fmt.Errorf("draft a runbook: %w", ai.ErrNoAnswer)
			}
			out.File, out.Valid, out.Plan, out.Problems, err = a.validateRunbookDraft(ctx, out.YAML)
			if err != nil {
				return err
			}
			detail["valid"] = out.Valid
			if out.Valid {
				return nil
			}
		}
		return nil
	})
	if err != nil {
		// No draft: the recording stays for another try.
		a.writeExplainError(w, r, err)
		return
	}
	// A draft was made: the recording is not kept for another.
	if !body.Preview {
		out.Discarded = a.recordings.drop(id)
	}
	writeJSON(w, http.StatusOK, out)
}

// validateRunbookDraft checks a draft as the runbook editor's save of a new
// file would, and plans a valid one. It writes, runs and audits nothing.
func (a *api) validateRunbookDraft(ctx context.Context, draft string) (string, bool, *automation.RunbookPlan, []automation.Problem, error) {
	refuse := func(file, msg string) (string, bool, *automation.RunbookPlan, []automation.Problem, error) {
		return file, false, nil, []automation.Problem{{Message: msg}}, nil
	}
	if len(draft) > maxAutomationBytes {
		return refuse("", fmt.Sprintf("the file is over %d KiB", maxAutomationBytes>>10))
	}
	name := runbookFileName(draft)
	if !automation.ValidDocName(name) {
		return refuse("", "the file needs an id: 1 to 64 lowercase letters, digits, - or _")
	}
	current, err := a.loadConfig(ctx)
	if err != nil {
		return "", false, nil, nil, err
	}
	if _, found := docOf(current, store.ConfigRunbook, name); found {
		return refuse(name, fmt.Sprintf("a runbook %s already exists: pick another id", name))
	}
	doc := hubconfig.Doc{Kind: store.ConfigRunbook, Name: name, Content: []byte(draft)}
	_, err = a.prepare(current, configWrite{incoming: []hubconfig.Doc{doc}})
	var invalid configInvalid
	switch {
	case errors.As(err, &invalid):
		return name, false, nil, configProblems(invalid.err), nil
	case err != nil:
		return "", false, nil, nil, err
	}
	plan, err := a.runbooks.PlanDraft(ctx, name, doc.Content)
	if err != nil {
		return name, false, nil, configProblems(err), nil
	}
	return name, true, plan, []automation.Problem{}, nil
}

// runbookInventory names what a runbook draft may refer to: what an
// automation draft may, but the runbook ids taken instead of the
// automation ids.
func (a *api) runbookInventory(ctx context.Context) []ai.Section {
	sections := slices.DeleteFunc(a.draftInventory(ctx), func(s ai.Section) bool {
		return s.ID == "automations"
	})
	var ids []string
	if all, _ := a.runbooks.List(ctx); all != nil {
		for _, rb := range all {
			ids = append(ids, rb.ID)
		}
	}
	slices.Sort(ids)
	return append(sections, ai.Section{ID: "runbooks", Title: "Existing runbook ids (do not reuse one)", Body: strings.Join(ids, "\n")})
}
