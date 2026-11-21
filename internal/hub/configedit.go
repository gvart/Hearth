// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/hubconfig"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// maxConfigBody bounds a configuration document from the web UI, as JSON.
const maxConfigBody = maxAutomationBody

// configEditRoutes registers the web UI's editors of the store's
// configuration documents. Each write is config.import by the web actor, as
// `hearth config import` is by the admin: validated first, as a whole, and
// held or denied as the policy says. Without documents there are none.
func (a *api) configEditRoutes(mux *http.ServeMux) {
	if !a.configEditable() {
		return
	}
	mux.Handle("GET /api/v1/policy", a.auth(a.getPolicyDoc))
	mux.Handle("POST /api/v1/policy/validate", a.auth(a.validatePolicyDoc))
	mux.Handle("PUT /api/v1/policy", a.auth(a.putPolicyDoc))
	mux.Handle("GET /api/v1/notify/config", a.auth(a.getNotifyConfig))
	mux.Handle("PUT /api/v1/notify/channels/{name}", a.auth(a.putNotifyChannel))
	mux.Handle("DELETE /api/v1/notify/channels/{name}", a.auth(a.deleteNotifyChannel))
	mux.Handle("GET /api/v1/runbook-files", a.auth(a.listRunbookFiles))
	mux.Handle("POST /api/v1/runbook-files/validate", a.auth(a.validateRunbookFile))
	mux.Handle("GET /api/v1/runbook-files/{file}", a.auth(a.getRunbookFile))
	mux.Handle("PUT /api/v1/runbook-files/{file}", a.auth(a.putRunbookFile))
	mux.Handle("DELETE /api/v1/runbook-files/{file}", a.auth(a.deleteRunbookFile))
	if a.automations.Docs != nil {
		mux.Handle("DELETE /api/v1/automations/{id}", a.auth(a.deleteAutomation))
	}
}

// configEditable says whether the store's documents can be edited here.
func (a *api) configEditable() bool { return a.configSealer != nil && a.configKinds != nil }

// errConfigChanged refuses a write made from a document that changed since
// the editor read it.
var errConfigChanged = errors.New("the document changed since it was opened")

// configInvalid is a configuration a write would leave that does not load,
// or a policy that would lock its editor out.
type configInvalid struct{ err error }

func (e configInvalid) Error() string { return e.err.Error() }

// configWrite is one write of documents from the web UI.
type configWrite struct {
	// incoming are the documents added or replaced; deleted, the one
	// removed (kind/name), if any.
	incoming               []hubconfig.Doc
	deleteKind, deleteName string
	// build makes incoming from the documents stored now, when the write
	// depends on them (a merge into notify.yaml); it may fail with
	// errConfigChanged, store.ErrNotFound or a configInvalid.
	build func(current []hubconfig.Doc) ([]hubconfig.Doc, error)
	// sensitive writes need the password entered again (recentAuth).
	sensitive bool
	// target and detail go into the audit entry: names, never content.
	target string
	detail map[string]any
}

// loadConfig reads the stored documents in clear.
func (a *api) loadConfig(ctx context.Context) ([]hubconfig.Doc, error) {
	return hubconfig.Load(ctx, a.store.ConfigDocs(), a.configSealer)
}

// prepare checks w against current: what it writes, validated with the rest
// of the configuration as the hub would load it, and sealed.
func (a *api) prepare(current []hubconfig.Doc, w configWrite) ([]store.ConfigDoc, error) {
	incoming := w.incoming
	if w.build != nil {
		var err error
		if incoming, err = w.build(current); err != nil {
			return nil, err
		}
	}
	if err := hubconfig.CheckWebLockout(incoming); err != nil {
		return nil, configInvalid{err}
	}
	after := hubconfig.Overlay(current, incoming)
	if w.deleteKind != "" {
		after = slices.DeleteFunc(after, func(d hubconfig.Doc) bool { return d.Kind == w.deleteKind && d.Name == w.deleteName })
	}
	if err := hubconfig.Validate(after, a.configKinds); err != nil {
		return nil, configInvalid{err}
	}
	return hubconfig.Seal(incoming, a.configSealer)
}

// writeConfig validates w and writes it through policy, as config.import by
// the web actor. It checks again once policy allowed it: approval may take
// minutes, and another hub or editor may write meanwhile.
func (a *api) writeConfig(r *http.Request, w configWrite) error {
	ctx := r.Context()
	current, err := a.loadConfig(ctx)
	if err != nil {
		return err
	}
	// Refused now, an invalid write is not held for approval first.
	if _, err := a.prepare(current, w); err != nil {
		return err
	}
	req := policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.ConfigImport,
		Target: w.target, Detail: w.detail,
	}
	if w.sensitive {
		req.Precheck = a.recentAuth(r)
	}
	return a.policy.Do(ctx, req, func(ctx context.Context) error {
		a.configMu.Lock()
		defer a.configMu.Unlock()
		current, err := a.loadConfig(ctx)
		if err != nil {
			return err
		}
		sealed, err := a.prepare(current, w)
		if err != nil {
			return err
		}
		docs := a.store.ConfigDocs()
		if len(sealed) > 0 {
			if err := docs.Put(ctx, policy.ActorWeb+"/"+remoteHost(r), sealed, a.now()); err != nil {
				return err
			}
		}
		if w.deleteKind != "" {
			return docs.Delete(ctx, w.deleteKind, w.deleteName)
		}
		return nil
	})
}

// ProblemsJSON answers a write of a configuration that does not load.
type ProblemsJSON struct {
	Error    string               `json:"error"`
	Code     string               `json:"code"`
	Problems []automation.Problem `json:"problems"`
}

// configProblems are the problems of err, one per line of its message.
// Messages never quote a notify value (see hubconfig.Parse).
func configProblems(err error) []automation.Problem {
	// One file's errors carry their lines; a whole configuration's are
	// joined, one per line.
	if _, ok := err.(*automation.LoadError); ok { //nolint:errorlint // only an unwrapped, unjoined one
		return automation.Problems(err)
	}
	var out []automation.Problem
	for _, line := range strings.Split(err.Error(), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, automation.Problem{Message: line})
		}
	}
	return out
}

// writeConfigError answers a failed write of configuration documents.
func (a *api) writeConfigError(w http.ResponseWriter, r *http.Request, op string, err error) {
	var invalid configInvalid
	switch {
	case errors.As(err, &invalid):
		writeJSON(w, http.StatusUnprocessableEntity, ProblemsJSON{
			Error: "the configuration is not valid", Code: "invalid", Problems: configProblems(invalid.err),
		})
	case errors.Is(err, errConfigChanged):
		writeError(w, http.StatusConflict, "revision_conflict",
			"the document changed since you opened it: reload it and apply your edit again")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such document")
	case errors.Is(err, automation.ErrExists):
		writeError(w, http.StatusConflict, "exists", "a document of this name already exists")
	default:
		a.writeActionError(w, r, op, err)
	}
}

// docOf is the document kind/name of docs, if there is one.
func docOf(docs []hubconfig.Doc, kind, name string) (hubconfig.Doc, bool) {
	i := slices.IndexFunc(docs, func(d hubconfig.Doc) bool { return d.Kind == kind && d.Name == name })
	if i < 0 {
		return hubconfig.Doc{}, false
	}
	return docs[i], true
}

// DocJSON is a configuration document as written, with the revision an edit
// of it must name.
type DocJSON struct {
	File     string `json:"file"`
	YAML     string `json:"yaml"`
	Revision string `json:"revision"`
}

// docBody is the body of a write or a validation of a document.
type docBody struct {
	YAML string `json:"yaml"`
	// Revision is the revision of the document the edit started from; ""
	// creates it.
	Revision string `json:"revision"`
	// File names a runbook being validated.
	File string `json:"file"`
}

// readDocBody decodes a document from the web UI, or answers the request
// and returns false.
func readDocBody(w http.ResponseWriter, r *http.Request) (docBody, bool) {
	var body docBody
	if !decodeJSON(w, r, maxConfigBody, &body, `{"yaml": "...", "revision": "..."}`) {
		return body, false
	}
	if len(body.YAML) > maxAutomationBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "a document may be at most 64 KiB")
		return body, false
	}
	return body, true
}

// checkRevision refuses an edit of doc (found, or not) that started from
// another revision than doc's now.
func checkRevision(doc hubconfig.Doc, found bool, revision string) error {
	switch {
	case revision == "" && found && len(doc.Content) > 0:
		return errConfigChanged
	case revision != "" && (!found || automation.Revision(doc.Content) != revision):
		return errConfigChanged
	}
	return nil
}

// getPolicyDoc serves policy.yaml as stored, to anyone signed in: it holds
// modes and names, no credentials.
func (a *api) getPolicyDoc(w http.ResponseWriter, r *http.Request) {
	docs, err := a.loadConfig(r.Context())
	if err != nil {
		a.writeActionError(w, r, "read the policy", err)
		return
	}
	doc, _ := docOf(docs, store.ConfigPolicy, hubconfig.PolicyFile)
	writeJSON(w, http.StatusOK, DocJSON{File: hubconfig.PolicyFile, YAML: string(doc.Content), Revision: automation.Revision(doc.Content)})
}

// ValidationJSON is the result of checking a document: nothing was written.
type ValidationJSON struct {
	Valid    bool                 `json:"valid"`
	Problems []automation.Problem `json:"problems"`
	// Plan is what a runbook's run would do.
	Plan *automation.RunbookPlan `json:"plan,omitempty"`
}

// validatePolicyDoc checks a policy as a save would, writing nothing.
func (a *api) validatePolicyDoc(w http.ResponseWriter, r *http.Request) {
	body, ok := readDocBody(w, r)
	if !ok {
		return
	}
	current, err := a.loadConfig(r.Context())
	if err != nil {
		a.writeActionError(w, r, "validate the policy", err)
		return
	}
	out := ValidationJSON{Valid: true, Problems: []automation.Problem{}}
	_, err = a.prepare(current, configWrite{incoming: []hubconfig.Doc{policyDoc(body.YAML)}})
	var invalid configInvalid
	if errors.As(err, &invalid) {
		out.Valid, out.Problems = false, configProblems(invalid.err)
	} else if err != nil {
		a.writeActionError(w, r, "validate the policy", err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func policyDoc(content string) hubconfig.Doc {
	return hubconfig.Doc{Kind: store.ConfigPolicy, Name: hubconfig.PolicyFile, Content: []byte(content)}
}

// putPolicyDoc replaces policy.yaml: the most powerful change there is, so
// it is sensitive and refused if it would lock the editor out.
func (a *api) putPolicyDoc(w http.ResponseWriter, r *http.Request) {
	body, ok := readDocBody(w, r)
	if !ok {
		return
	}
	doc := policyDoc(body.YAML)
	err := a.writeConfig(r, configWrite{
		build: func(current []hubconfig.Doc) ([]hubconfig.Doc, error) {
			// No stored policy reads as an empty one, as GET serves it.
			stored, _ := docOf(current, store.ConfigPolicy, hubconfig.PolicyFile)
			if body.Revision != automation.Revision(stored.Content) {
				return nil, errConfigChanged
			}
			return []hubconfig.Doc{doc}, nil
		},
		sensitive: true, target: doc.ID(),
		detail: map[string]any{"documents": []string{doc.ID()}, "sha256": automation.Revision(doc.Content)},
	})
	if err != nil {
		a.writeConfigError(w, r, "save the policy", err)
		return
	}
	writeJSON(w, http.StatusOK, DocJSON{File: doc.Name, YAML: body.YAML, Revision: automation.Revision(doc.Content)})
}

// NotifyChannelJSON is a channel as the editor shows it: its name, its type,
// and which of its fields are set. No value is ever served: every field is an
// address or a credential.
type NotifyChannelJSON struct {
	Name string          `json:"name"`
	Type string          `json:"type"`
	Set  map[string]bool `json:"set"`
}

// notifyFields are a channel's write-only fields, by type.
var notifyFields = map[string][]string{
	"ntfy":     {"url", "topic", "token"},
	"telegram": {"bot_token", "chat_id"},
}

// fieldOf is the field name of c.
func fieldOf(c *notify.FileChannel, name string) *string {
	switch name {
	case "url":
		return &c.URL
	case "topic":
		return &c.Topic
	case "token":
		return &c.Token
	case "bot_token":
		return &c.BotToken
	case "chat_id":
		return &c.ChatID
	}
	return nil
}

// notifyFile is the stored notify.yaml, parsed; empty without one.
func notifyFile(current []hubconfig.Doc) (notify.File, error) {
	doc, _ := docOf(current, store.ConfigNotify, hubconfig.NotifyFile)
	f, err := notify.ParseFile(doc.Content)
	if err != nil {
		return notify.File{}, configInvalid{errors.New(hubconfig.NotifyFile + ": the stored file does not parse: fix it with `hearth config import`")}
	}
	if f.Channels == nil {
		f.Channels = map[string]notify.FileChannel{}
	}
	return f, nil
}

func (a *api) getNotifyConfig(w http.ResponseWriter, r *http.Request) {
	current, err := a.loadConfig(r.Context())
	if err != nil {
		a.writeActionError(w, r, "read the notification channels", err)
		return
	}
	f, err := notifyFile(current)
	if err != nil {
		a.writeConfigError(w, r, "read the notification channels", err)
		return
	}
	out := make([]NotifyChannelJSON, 0, len(f.Channels))
	for name, c := range f.Channels {
		set := map[string]bool{}
		for _, field := range notifyFields[c.Type] {
			set[field] = *fieldOf(&c, field) != ""
		}
		out = append(out, NotifyChannelJSON{Name: name, Type: c.Type, Set: set})
	}
	slices.SortFunc(out, func(x, y NotifyChannelJSON) int { return strings.Compare(x.Name, y.Name) })
	writeJSON(w, http.StatusOK, struct {
		Channels []NotifyChannelJSON `json:"channels"`
	}{Channels: out})
}

// notifyChannelBody is an edit of a channel: an empty field keeps the value
// stored for it, while the type stays; Clear empties fields.
type notifyChannelBody struct {
	Type     string   `json:"type"`
	URL      string   `json:"url"`
	Topic    string   `json:"topic"`
	Token    string   `json:"token"`
	BotToken string   `json:"bot_token"`
	ChatID   string   `json:"chat_id"`
	Clear    []string `json:"clear"`
}

// putNotifyChannel adds or edits a channel of notify.yaml, merged into the
// stored file: sensitive, as it changes where notifications and approval
// links go. The file is sealed before it is stored, and no value is logged,
// audited or served.
func (a *api) putNotifyChannel(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body notifyChannelBody
	if !decodeJSON(w, r, maxTokenBody, &body, `{"type": "ntfy|telegram", ...fields}`) {
		return
	}
	if _, ok := notifyFields[body.Type]; !ok {
		writeError(w, http.StatusBadRequest, "bad_type", "the type must be ntfy or telegram")
		return
	}
	for _, field := range body.Clear {
		if !slices.Contains(notifyFields[body.Type], field) {
			writeError(w, http.StatusBadRequest, "bad_field", "only a field of the channel's type can be cleared")
			return
		}
	}
	id := store.ConfigDocID(store.ConfigNotify, hubconfig.NotifyFile)
	err := a.writeConfig(r, configWrite{
		build: func(current []hubconfig.Doc) ([]hubconfig.Doc, error) {
			f, err := notifyFile(current)
			if err != nil {
				return nil, err
			}
			c := f.Channels[name]
			if c.Type != body.Type {
				// Nothing of another type's channel carries over.
				c = notify.FileChannel{Type: body.Type}
			}
			given := notify.FileChannel{URL: body.URL, Topic: body.Topic, Token: body.Token, BotToken: body.BotToken, ChatID: body.ChatID}
			for _, field := range notifyFields[body.Type] {
				if v := *fieldOf(&given, field); v != "" {
					*fieldOf(&c, field) = v
				}
				if slices.Contains(body.Clear, field) {
					*fieldOf(&c, field) = ""
				}
			}
			f.Channels[name] = c
			return notifyDocs(f)
		},
		sensitive: true, target: id,
		detail: map[string]any{"documents": []string{id}, "channel": name},
	})
	if err != nil {
		a.writeConfigError(w, r, "save the notification channel", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// notifyDocs is f as the notify document.
func notifyDocs(f notify.File) ([]hubconfig.Doc, error) {
	b, err := yaml.Marshal(f)
	if err != nil {
		return nil, err
	}
	return []hubconfig.Doc{{Kind: store.ConfigNotify, Name: hubconfig.NotifyFile, Content: b}}, nil
}

// deleteNotifyChannel removes a channel from notify.yaml. A channel an
// automation or the approval notifications still use cannot go: the
// configuration would not load.
func (a *api) deleteNotifyChannel(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	id := store.ConfigDocID(store.ConfigNotify, hubconfig.NotifyFile)
	err := a.writeConfig(r, configWrite{
		build: func(current []hubconfig.Doc) ([]hubconfig.Doc, error) {
			f, err := notifyFile(current)
			if err != nil {
				return nil, err
			}
			if _, ok := f.Channels[name]; !ok {
				return nil, store.ErrNotFound
			}
			delete(f.Channels, name)
			return notifyDocs(f)
		},
		sensitive: true, target: id,
		detail: map[string]any{"documents": []string{id}, "channel": name, "delete": true},
	})
	if err != nil {
		a.writeConfigError(w, r, "delete the notification channel", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RunbookFileJSON is a runbook document in the list.
type RunbookFileJSON struct {
	File string `json:"file"`
	// ID is the id the file declares; "" if it declares none.
	ID string `json:"id"`
}

// declaredID is the id a runbook or automation file declares, if it parses
// that far.
func declaredID(content []byte) string {
	var head struct {
		ID string `yaml:"id"`
	}
	_ = yaml.Unmarshal(content, &head)
	return head.ID
}

func (a *api) listRunbookFiles(w http.ResponseWriter, r *http.Request) {
	current, err := a.loadConfig(r.Context())
	if err != nil {
		a.writeActionError(w, r, "list the runbook files", err)
		return
	}
	out := []RunbookFileJSON{}
	for _, d := range current {
		if d.Kind == store.ConfigRunbook {
			out = append(out, RunbookFileJSON{File: d.Name, ID: declaredID(d.Content)})
		}
	}
	writeJSON(w, http.StatusOK, struct {
		Files []RunbookFileJSON `json:"files"`
	}{Files: out})
}

// runbookFile is the file named in the path, or an answer and false.
func runbookFile(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("file")
	if !automation.ValidDocName(name) {
		writeError(w, http.StatusBadRequest, "bad_name", "a runbook file is named like upgrade-app.yaml")
		return "", false
	}
	return name, true
}

// getRunbookFile serves a runbook file as written. It may hold secrets, such
// as a webhook's URL: it goes to the signed-in admin only, never to a log.
func (a *api) getRunbookFile(w http.ResponseWriter, r *http.Request) {
	name, ok := runbookFile(w, r)
	if !ok {
		return
	}
	current, err := a.loadConfig(r.Context())
	if err != nil {
		a.writeActionError(w, r, "read the runbook", err)
		return
	}
	doc, found := docOf(current, store.ConfigRunbook, name)
	if !found {
		writeError(w, http.StatusNotFound, "not_found", "no such runbook file")
		return
	}
	writeJSON(w, http.StatusOK, DocJSON{File: name, YAML: string(doc.Content), Revision: automation.Revision(doc.Content)})
}

// validateRunbookFile checks a runbook file as a save would, and says what a
// run would do. It writes, runs and audits nothing.
func (a *api) validateRunbookFile(w http.ResponseWriter, r *http.Request) {
	body, ok := readDocBody(w, r)
	if !ok {
		return
	}
	name := body.File
	if name == "" {
		name = runbookFileName(body.YAML)
	}
	if !automation.ValidDocName(name) {
		writeError(w, http.StatusBadRequest, "bad_name", "a runbook file is named like upgrade-app.yaml")
		return
	}
	current, err := a.loadConfig(r.Context())
	if err != nil {
		a.writeActionError(w, r, "validate the runbook", err)
		return
	}
	out := ValidationJSON{Valid: true, Problems: []automation.Problem{}}
	doc := hubconfig.Doc{Kind: store.ConfigRunbook, Name: name, Content: []byte(body.YAML)}
	_, err = a.prepare(current, configWrite{incoming: []hubconfig.Doc{doc}})
	var invalid configInvalid
	switch {
	case errors.As(err, &invalid):
		out.Valid, out.Problems = false, configProblems(invalid.err)
	case err != nil:
		a.writeActionError(w, r, "validate the runbook", err)
		return
	case a.runbooks != nil:
		if out.Plan, err = a.runbooks.PlanDraft(r.Context(), name, doc.Content); err != nil {
			out.Valid, out.Problems = false, configProblems(err)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// runbookFileName is the file a new runbook goes in: its id.yaml.
func runbookFileName(content string) string {
	id := declaredID([]byte(content))
	if id == "" {
		return ""
	}
	return id + ".yaml"
}

// putRunbookFile creates or replaces a runbook file: config.import, as
// `hearth config import` of the file would be. A new file's name must be
// its id.yaml.
func (a *api) putRunbookFile(w http.ResponseWriter, r *http.Request) {
	name, ok := runbookFile(w, r)
	if !ok {
		return
	}
	body, ok := readDocBody(w, r)
	if !ok {
		return
	}
	if body.Revision == "" && name != runbookFileName(body.YAML) {
		writeError(w, http.StatusBadRequest, "bad_name", "a new runbook's file is named after its id: <id>.yaml")
		return
	}
	doc := hubconfig.Doc{Kind: store.ConfigRunbook, Name: name, Content: []byte(body.YAML)}
	create := body.Revision == ""
	err := a.writeConfig(r, configWrite{
		build: func(current []hubconfig.Doc) ([]hubconfig.Doc, error) {
			stored, found := docOf(current, store.ConfigRunbook, name)
			if create && found {
				return nil, automation.ErrExists
			}
			if err := checkRevision(stored, found, body.Revision); err != nil {
				return nil, err
			}
			return []hubconfig.Doc{doc}, nil
		},
		target: doc.ID(),
		detail: map[string]any{"documents": []string{doc.ID()}, "sha256": automation.Revision(doc.Content), "create": create},
	})
	if err != nil {
		a.writeConfigError(w, r, "save the runbook", err)
		return
	}
	status := http.StatusOK
	if create {
		status = http.StatusCreated
	}
	writeJSON(w, status, DocJSON{File: name, YAML: body.YAML, Revision: automation.Revision(doc.Content)})
}

// deleteRunbookFile deletes a runbook file, as `hearth config delete
// runbook` does. Runs already started keep their own copy of it.
func (a *api) deleteRunbookFile(w http.ResponseWriter, r *http.Request) {
	name, ok := runbookFile(w, r)
	if !ok {
		return
	}
	a.deleteDoc(w, r, store.ConfigRunbook, name, "delete the runbook")
}

// deleteAutomation deletes an automation's document, as `hearth config
// delete automation` does: every hub stops running it.
func (a *api) deleteAutomation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !automation.ValidID(id) {
		writeError(w, http.StatusBadRequest, "bad_id", "not an automation id")
		return
	}
	f, err := a.automations.Get(r.Context(), id)
	if err != nil {
		a.writeAutomationError(w, r, "delete automation", err)
		return
	}
	a.deleteDoc(w, r, store.ConfigAutomation, f.Path, "delete the automation")
}

// deleteDoc deletes the document kind/name through policy (config.import).
func (a *api) deleteDoc(w http.ResponseWriter, r *http.Request, kind, name, op string) {
	id := store.ConfigDocID(kind, name)
	err := a.writeConfig(r, configWrite{
		deleteKind: kind, deleteName: name,
		build: func(current []hubconfig.Doc) ([]hubconfig.Doc, error) {
			if _, found := docOf(current, kind, name); !found {
				return nil, store.ErrNotFound
			}
			return nil, nil
		},
		target: id, detail: map[string]any{"delete": id},
	})
	if err != nil {
		a.writeConfigError(w, r, op, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
