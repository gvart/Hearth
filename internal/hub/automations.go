// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"path/filepath"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const (
	// maxAutomationBytes bounds an automation file from the web UI.
	maxAutomationBytes = 64 << 10
	// maxAutomationBody bounds its request: JSON may escape every byte.
	maxAutomationBody = 6*maxAutomationBytes + 4<<10
)

// automationRoutes registers the automation editor's API, behind the admin
// session. Without an automations directory there are no routes.
func (a *api) automationRoutes(mux *http.ServeMux) {
	if a.automations.Dir == "" {
		return
	}
	mux.Handle("GET /api/v1/automations", a.auth(a.listAutomations))
	mux.Handle("POST /api/v1/automations", a.auth(a.createAutomation))
	mux.Handle("POST /api/v1/automations/dry-run", a.auth(a.dryRunAutomation))
	mux.Handle("GET /api/v1/automations/{id}", a.auth(a.getAutomation))
	mux.Handle("PUT /api/v1/automations/{id}", a.auth(a.updateAutomation))
}

// AutomationJSON is one automation file in the list.
type AutomationJSON struct {
	// ID is "" for a file that declares none, which cannot be opened here.
	ID          string `json:"id"`
	File        string `json:"file"`
	Description string `json:"description"`
	Mode        string `json:"mode"`
	Triggers    int    `json:"triggers"`
	Actions     int    `json:"actions"`
	// Problems say why the hub cannot load the file.
	Problems []automation.Problem `json:"problems"`
}

func (a *api) listAutomations(w http.ResponseWriter, r *http.Request) {
	files, err := a.automations.List()
	if err != nil {
		a.log.ErrorContext(r.Context(), "list automations", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot read the automations directory")
		return
	}
	out := make([]AutomationJSON, 0, len(files))
	for _, f := range files {
		item := AutomationJSON{ID: f.ID, File: filepath.Base(f.Path), Problems: []automation.Problem{}}
		if f.Err != nil {
			item.Problems = automation.Problems(f.Err)
		} else {
			item.Description, item.Mode = f.Automation.Description, string(f.Automation.Mode)
			item.Triggers, item.Actions = len(f.Automation.Triggers), len(f.Automation.Actions)
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, struct {
		Automations []AutomationJSON `json:"automations"`
	}{Automations: out})
}

// AutomationSourceJSON is an automation file as written. Its YAML may hold
// secrets, such as a webhook's URL: it goes to the signed-in admin only, and
// never into a log or the audit log.
type AutomationSourceJSON struct {
	ID       string               `json:"id"`
	File     string               `json:"file"`
	YAML     string               `json:"yaml"`
	Revision string               `json:"revision"`
	Problems []automation.Problem `json:"problems"`
}

func (a *api) getAutomation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !automation.ValidID(id) {
		writeError(w, http.StatusBadRequest, "bad_id", "not an automation id")
		return
	}
	f, err := a.automations.Get(id)
	if err != nil {
		a.writeAutomationError(w, r, "get automation", err)
		return
	}
	out := AutomationSourceJSON{
		ID: f.ID, File: filepath.Base(f.Path), YAML: string(f.Content), Revision: automation.Revision(f.Content),
		Problems: []automation.Problem{},
	}
	if f.Err != nil {
		out.Problems = automation.Problems(f.Err)
	}
	writeJSON(w, http.StatusOK, out)
}

// automationBody is the body of a save or a dry run.
type automationBody struct {
	YAML string `json:"yaml"`
	// Revision is the revision of the file the edit started from.
	Revision string `json:"revision"`
	// ID, in a dry run, is the automation being edited; "" for a new one.
	ID string `json:"id"`
}

// readAutomationBody decodes the request, or answers it and returns false.
func readAutomationBody(w http.ResponseWriter, r *http.Request) (automationBody, bool) {
	var body automationBody
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return body, false
	}
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAutomationBody)).Decode(&body)
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig) || len(body.YAML) > maxAutomationBytes:
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "an automation file may be at most 64 KiB")
		return body, false
	case err != nil:
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"yaml": "...", "revision": "..."}`)
		return body, false
	}
	return body, true
}

func (a *api) createAutomation(w http.ResponseWriter, r *http.Request) {
	body, ok := readAutomationBody(w, r)
	if ok {
		a.saveAutomation(w, r, body, "")
	}
}

func (a *api) updateAutomation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !automation.ValidID(id) {
		writeError(w, http.StatusBadRequest, "bad_id", "not an automation id")
		return
	}
	body, ok := readAutomationBody(w, r)
	if ok {
		a.saveAutomation(w, r, body, id)
	}
}

// saveAutomation validates the file as the hub would load it and writes it
// through policy. id is the automation it replaces; "" creates a new one.
func (a *api) saveAutomation(w http.ResponseWriter, r *http.Request, body automationBody, id string) {
	ctx := r.Context()
	content := []byte(body.YAML)
	parsed, err := automation.Parse(automationFileName(id), content, a.automations.Kinds)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, automationInvalidJSON{
			Error: "the automation is not valid", Code: "invalid", Problems: automation.Problems(err),
		})
		return
	}
	create := id == ""
	if !create && parsed.ID != id {
		writeError(w, http.StatusBadRequest, "id_mismatch", "the file's id must stay "+id+": renaming is not supported")
		return
	}
	// Refused now, a stale save is not held for approval first.
	path, err := a.automations.Target(parsed, create, body.Revision)
	if err != nil {
		a.writeAutomationError(w, r, "save automation", err)
		return
	}
	revision := automation.Revision(content)
	err = a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb,
		ActorID:   remoteHost(r),
		Action:    policy.AutomationApply,
		Target:    parsed.ID,
		Detail:    automationAuditDetail(parsed, path, revision, create),
	}, func(context.Context) error {
		a.automationsMu.Lock()
		defer a.automationsMu.Unlock()
		// Approval can take minutes: judge the directory as it is now.
		path, err := a.automations.Target(parsed, create, body.Revision)
		if err != nil {
			return err
		}
		return automation.WriteFile(a.automations.Dir, path, content)
	})
	if err != nil {
		a.writeAutomationError(w, r, "save automation", err)
		return
	}
	status := http.StatusOK
	if create {
		status = http.StatusCreated
	}
	writeJSON(w, status, struct {
		ID       string `json:"id"`
		File     string `json:"file"`
		Revision string `json:"revision"`
	}{ID: parsed.ID, File: filepath.Base(path), Revision: revision})
}

// automationFileName names a file being validated in its problems.
func automationFileName(id string) string {
	if id == "" {
		return "automation.yaml"
	}
	return id + ".yaml"
}

// automationAuditDetail says what is being saved. It names the steps and
// their policy actions and identifies the content by hash: the file's values
// may be secrets, which the audit log must not hold.
func automationAuditDetail(p *automation.Automation, path, revision string, create bool) map[string]any {
	steps := make([]map[string]string, 0, len(p.Actions))
	for _, s := range p.Actions {
		steps = append(steps, map[string]string{"id": s.ID, "type": s.Type, "policy": string(s.Impl.Policy())})
	}
	return map[string]any{"file": filepath.Base(path), "sha256": revision, "create": create, "actions": steps}
}

// automationInvalidJSON answers a save of an invalid file.
type automationInvalidJSON struct {
	Error    string               `json:"error"`
	Code     string               `json:"code"`
	Problems []automation.Problem `json:"problems"`
}

// AutomationDecisionJSON is what policy would decide on saving the file.
type AutomationDecisionJSON struct {
	Action   string `json:"action"`
	Class    string `json:"class"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// AutomationDryRunJSON is the result of a dry run: nothing was written or run.
type AutomationDryRunJSON struct {
	Valid    bool                 `json:"valid"`
	Problems []automation.Problem `json:"problems"`
	// Blocked says why a valid file could not be saved now.
	Blocked string `json:"blocked,omitempty"`
	// Plan describes what the automation would do.
	Plan string `json:"plan,omitempty"`
	// Save is policy's decision on saving the file.
	Save *AutomationDecisionJSON `json:"save,omitempty"`
	// Actions are policy's decisions on each action when the automation runs.
	Actions []automation.ActionDecision `json:"actions"`
}

// dryRunAutomation validates the file and asks policy about saving it and
// about each of its actions, auditing those decisions as dry runs. It writes
// no file, starts no trigger and runs no action.
func (a *api) dryRunAutomation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	body, ok := readAutomationBody(w, r)
	if !ok {
		return
	}
	out := AutomationDryRunJSON{Problems: []automation.Problem{}, Actions: []automation.ActionDecision{}}
	parsed, err := automation.Parse(automationFileName(body.ID), []byte(body.YAML), a.automations.Kinds)
	if err != nil {
		out.Problems = automation.Problems(err)
		writeJSON(w, http.StatusOK, out)
		return
	}
	out.Valid = true
	var plan bytes.Buffer
	if err := automation.Plan(&plan, parsed); err != nil {
		a.log.ErrorContext(ctx, "plan automation", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot describe the automation")
		return
	}
	out.Plan = plan.String()

	create := body.ID == ""
	path := filepath.Join(a.automations.Dir, parsed.ID+".yaml")
	if !create && parsed.ID != body.ID {
		out.Blocked = "the file's id must stay " + body.ID + ": renaming is not supported"
	} else if p, err := a.automations.Target(parsed, create, body.Revision); err != nil {
		out.Blocked = err.Error()
	} else {
		path = p
	}

	req := policy.Request{
		ActorKind: policy.ActorWeb,
		ActorID:   remoteHost(r),
		Action:    policy.AutomationApply,
		Target:    parsed.ID,
		Detail:    automationAuditDetail(parsed, path, automation.Revision([]byte(body.YAML)), create),
		DryRun:    true,
	}
	class, _ := policy.ClassOf(req.Action)
	save := &AutomationDecisionJSON{Action: string(req.Action), Class: string(class)}
	err = a.policy.Do(ctx, req, func(context.Context) error { return nil })
	switch {
	case errors.Is(err, policy.ErrDenied):
		save.Decision, save.Reason = a.policy.Check(req)
	case err != nil:
		a.writeAutomationError(w, r, "dry run automation", err)
		return
	default:
		save.Decision, save.Reason = a.policy.Check(req)
	}
	out.Save = save

	out.Actions, err = automation.DryRun(ctx, parsed, a.policy, policy.ActorWeb+"/"+remoteHost(r))
	if err != nil {
		a.writeAutomationError(w, r, "dry run automation", err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// writeAutomationError answers a failed read or save of an automation file.
func (a *api) writeAutomationError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, automation.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such automation")
	case errors.Is(err, automation.ErrExists):
		writeError(w, http.StatusConflict, "exists", err.Error())
	case errors.Is(err, automation.ErrRevision):
		writeError(w, http.StatusConflict, "revision_conflict",
			"the file changed since you opened it: reload it and apply your edit again")
	case errors.Is(err, automation.ErrDirInvalid):
		writeError(w, http.StatusConflict, "directory_invalid", err.Error())
	case errors.Is(err, automation.ErrNotRegular):
		writeError(w, http.StatusConflict, "not_regular", "this file is a link: edit it where it lives")
	case r.Context().Err() != nil:
		// The client went away.
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(r.Context(), op, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot save the automation")
	}
}
