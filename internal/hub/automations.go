// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const (
	// maxAutomationBytes bounds an automation file from the web UI.
	maxAutomationBytes = 64 << 10
	// maxAutomationBody bounds its request: JSON may escape every byte.
	maxAutomationBody = 6*maxAutomationBytes + 4<<10
	// maxAutomationSteps bounds a file from the web UI: every action of a dry
	// run adds a row to the audit log.
	maxAutomationSteps = 64
	// dryRunBurst and dryRunEvery set the per-client rate of dry runs.
	dryRunBurst = 20
	dryRunEvery = 3 * time.Second
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
		if f.Linked {
			// Nothing of what it points to is shown.
			item.ID = ""
			item.Problems = []automation.Problem{{Message: "This file is a link: edit it where it lives."}}
		} else if f.Err != nil {
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
	// Before the file is read: parsing it runs its templates.
	req := a.saveRequest(r, id)
	if decision, _ := a.policy.Check(req); decision == policy.Deny {
		a.writeAutomationError(w, r, "save automation", a.policy.Do(ctx, req, func(context.Context) error { return nil }))
		return
	}
	content := []byte(body.YAML)
	parsed, err := a.parseAutomation(id, content)
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
	req.Target, req.Detail = parsed.ID, automationAuditDetail(parsed, path, revision, create)
	err = a.savePolicy(parsed).Do(ctx, req, func(context.Context) error {
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
	writeJSON(w, status, AutomationSavedJSON{
		ID: parsed.ID, File: filepath.Base(path), Revision: revision,
		Hub: r.Host, Cluster: len(a.leadership.AgentURLs()) > 0, Leader: a.leadership.IsLeader(),
	})
}

// AutomationSavedJSON answers a save. The file is written on this hub only,
// and only the cluster's leader runs automations.
type AutomationSavedJSON struct {
	ID       string `json:"id"`
	File     string `json:"file"`
	Revision string `json:"revision"`
	// Hub is the address of the hub that holds the file now.
	Hub string `json:"hub"`
	// Cluster says this hub is one of several.
	Cluster bool `json:"cluster"`
	// Leader says this hub runs automations now.
	Leader bool `json:"leader"`
}

// saveRequest is the policy request to save the automation id.
func (a *api) saveRequest(r *http.Request, id string) policy.Request {
	return policy.Request{
		ActorKind: policy.ActorWeb,
		ActorID:   remoteHost(r),
		Action:    policy.AutomationApply,
		Target:    id,
	}
}

// savePolicy is the engine that decides on saving p. A grant of dangerous
// actions belongs to an id, so a file that uses one is approved by a person
// whatever the modes say: its author would otherwise inherit the grant.
func (a *api) savePolicy(p *automation.Automation) *policy.Engine {
	if !a.policy.GrantedDangerous(p.ID) {
		return a.policy
	}
	for _, s := range p.Actions {
		if class, _ := policy.ClassOf(s.Impl.Policy()); class == policy.Dangerous {
			return a.policy.Holding(policy.ActorWeb, policy.Dangerous)
		}
	}
	return a.policy
}

// parseAutomation validates a file from the web UI.
func (a *api) parseAutomation(id string, content []byte) (*automation.Automation, error) {
	name := automationFileName(id)
	parsed, err := automation.Parse(name, content, a.automations.Kinds)
	if err != nil {
		return nil, err
	}
	if n := len(parsed.Triggers) + len(parsed.Conditions) + len(parsed.Actions); n > maxAutomationSteps {
		return nil, &automation.LoadError{File: name, Errs: []error{
			fmt.Errorf("an automation may have at most %d steps, this one has %d", maxAutomationSteps, n),
		}}
	}
	return parsed, nil
}

// automationFileName names a file being validated in its problems.
func automationFileName(id string) string {
	if id == "" {
		return "automation.yaml"
	}
	return id + ".yaml"
}

// automationAuditDetail says what is being saved. The plan is what an approver
// decides on: it shows each command and its device, and of a webhook only the
// site, never its URL, headers or body, which may be secrets.
func automationAuditDetail(p *automation.Automation, path, revision string, create bool) map[string]any {
	steps := make([]map[string]string, 0, len(p.Actions))
	for _, s := range p.Actions {
		steps = append(steps, map[string]string{"id": s.ID, "type": s.Type, "policy": string(s.Impl.Policy())})
	}
	return map[string]any{
		"file": filepath.Base(path), "sha256": revision, "create": create, "actions": steps, "plan": automationPlan(p),
	}
}

// automationPlan describes p for someone deciding whether to save it.
func automationPlan(p *automation.Automation) string {
	var b strings.Builder
	if err := automation.Plan(&b, p); err != nil {
		return "" // a strings.Builder does not fail
	}
	return strings.TrimSuffix(b.String(), "\nDry run: nothing was executed.\n")
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
	if ok, wait := a.dryRuns.allow(remoteHost(r)); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many dry runs: wait a moment and try again")
		return
	}
	body, ok := readAutomationBody(w, r)
	if !ok {
		return
	}
	out := AutomationDryRunJSON{Problems: []automation.Problem{}, Actions: []automation.ActionDecision{}}
	// Before the file is read: parsing it runs its templates.
	denied := a.saveRequest(r, body.ID)
	denied.DryRun = true
	if decision, reason := a.policy.Check(denied); decision == policy.Deny {
		if err := a.policy.Do(ctx, denied, func(context.Context) error { return nil }); err != nil && !errors.Is(err, policy.ErrDenied) {
			a.writeAutomationError(w, r, "dry run automation", err)
			return
		}
		class, _ := policy.ClassOf(denied.Action)
		out.Blocked = "Policy does not allow saving automations here, so the file was not checked."
		out.Save = &AutomationDecisionJSON{Action: string(denied.Action), Class: string(class), Decision: decision, Reason: reason}
		writeJSON(w, http.StatusOK, out)
		return
	}
	parsed, err := a.parseAutomation(body.ID, []byte(body.YAML))
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
		_, _, out.Blocked = automationRefusal(err)
		a.log.WarnContext(ctx, "dry run automation: the save would be refused", "automation", parsed.ID, "err", err)
	} else {
		path = p
	}

	req := a.saveRequest(r, parsed.ID)
	req.Detail = automationAuditDetail(parsed, path, automation.Revision([]byte(body.YAML)), create)
	req.DryRun = true
	class, _ := policy.ClassOf(req.Action)
	save := &AutomationDecisionJSON{Action: string(req.Action), Class: string(class)}
	engine := a.savePolicy(parsed)
	if err := engine.Do(ctx, req, func(context.Context) error { return nil }); err != nil && !errors.Is(err, policy.ErrDenied) {
		a.writeAutomationError(w, r, "dry run automation", err)
		return
	}
	save.Decision, save.Reason = engine.Check(req)
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
	status, code, message := automationRefusal(err)
	switch {
	case status != http.StatusInternalServerError:
		if errors.Is(err, automation.ErrDirInvalid) {
			a.log.WarnContext(r.Context(), op, "err", err)
		}
		writeError(w, status, code, message)
	case r.Context().Err() != nil:
		// The client went away.
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(r.Context(), op, "err", err)
		writeError(w, status, code, message)
	}
}

// automationRefusal says how to answer err. The message is fixed text: an
// error from the file system names paths on the hub.
func automationRefusal(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, policy.ErrDenied):
		return http.StatusForbidden, "forbidden", "denied by policy"
	case errors.Is(err, automation.ErrNotFound):
		return http.StatusNotFound, "not_found", "no such automation"
	case errors.Is(err, automation.ErrExists):
		return http.StatusConflict, "exists", "an automation with this id already exists"
	case errors.Is(err, automation.ErrRevision):
		return http.StatusConflict, "revision_conflict",
			"the file changed since you opened it: reload it and apply your edit again"
	case errors.Is(err, automation.ErrDirInvalid):
		return http.StatusConflict, "directory_invalid", "another automation file is invalid: fix it first"
	case errors.Is(err, automation.ErrNotRegular):
		return http.StatusConflict, "not_regular", "this file is a link: edit it where it lives"
	}
	return http.StatusInternalServerError, "internal", "cannot save the automation"
}
