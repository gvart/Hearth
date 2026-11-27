// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// Guest and kiosk panels (docs/panels.md).
//
// A signed-in admin builds a panel: a name and an ordered list of widgets,
// each pointing at one entity and listing the actions a guest may take on
// it. Only read and safe actions that admit policy.ActorGuest can be listed:
// a dangerous one is refused when the panel is saved. A share link opens one
// panel without a login (see guest.go).

const (
	// widgetDevice is a widget showing one enrolled device.
	widgetDevice = "device"
	// maxPanelBody bounds a panel save.
	maxPanelBody = 64 << 10
	// maxPanelWidgets and maxWidgetActions bound a panel.
	maxPanelWidgets  = 50
	maxWidgetActions = 20
	// maxPanelName bounds a panel's name, in runes.
	maxPanelName = 100
	// panelLinkPath is the web UI route of a share link; the secret follows.
	panelLinkPath = "/p/"
)

// panelActions are the actions a widget of each kind may offer its guests.
// policy decides each one again when a guest takes it.
var panelActions = map[string][]policy.Action{
	widgetDevice: {policy.DeviceRestart},
}

// PanelActionJSON is one action a widget allows its guests.
type PanelActionJSON struct {
	// ID is the action's key within its widget, set by the hub.
	ID     string `json:"id"`
	Action string `json:"action"`
	// Service is the service a device.restart restarts, as manager:name.
	Service string `json:"service,omitempty"`
	// Class is the action's policy class, set by the hub.
	Class string `json:"class"`
}

// PanelWidgetJSON is one widget of a panel.
type PanelWidgetJSON struct {
	// ID is the widget's key within its panel; the hub sets it when it is
	// missing.
	ID string `json:"id"`
	// Kind is the kind of entity: device.
	Kind string `json:"kind"`
	// Entity is the entity's ID: a device ID.
	Entity  string            `json:"entity"`
	Actions []PanelActionJSON `json:"actions"`
}

// PanelLinkJSON is a share link of a panel, without its secret.
type PanelLinkJSON struct {
	ID        string     `json:"id"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	// Status is active, expired or revoked.
	Status string `json:"status"`
}

// PanelJSON is the admin's view of a panel.
type PanelJSON struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Widgets   []PanelWidgetJSON `json:"widgets"`
	Links     []PanelLinkJSON   `json:"links"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// CreatedPanelLinkJSON answers the creation of a share link: the only time
// its secret is shown.
type CreatedPanelLinkJSON struct {
	Link  PanelLinkJSON `json:"link"`
	Token string        `json:"token"`
	// Path is the web UI path that opens the panel: /p/<token>.
	Path string `json:"path"`
}

// panelRoutes registers the admin's panel API, behind the admin session.
func (a *api) panelRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/panels", a.auth(a.listPanels))
	mux.Handle("POST /api/v1/panels", a.auth(a.createPanel))
	mux.Handle("GET /api/v1/panels/{id}", a.auth(a.getPanel))
	mux.Handle("PUT /api/v1/panels/{id}", a.auth(a.updatePanel))
	mux.Handle("DELETE /api/v1/panels/{id}", a.auth(a.deletePanel))
	mux.Handle("POST /api/v1/panels/{id}/links", a.auth(a.createPanelLink))
	mux.Handle("DELETE /api/v1/panels/{id}/links/{link}", a.auth(a.revokePanelLink))
}

// errBadPanel is a panel the admin cannot save; errDangerousAction one that
// lists a dangerous action. Their messages are for the admin.
var (
	errBadPanel        = errors.New("bad panel")
	errDangerousAction = errors.New("a panel cannot allow a dangerous action")
)

// widgetIDPattern is the shape of a widget ID the hub made.
var widgetIDPattern = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(`^[a-z0-9]{1,32}$`) })

// serviceManagers are the managers a restart may name, as the agent's
// --allow-restart does.
var serviceManagers = []string{"systemd", "systemd-user", "docker"}

// validService checks a manager:name service a restart widget names.
func validService(s string) bool {
	manager, name, ok := strings.Cut(s, ":")
	return ok && name != "" && len(s) <= 256 && slices.Contains(serviceManagers, manager) &&
		!strings.ContainsFunc(name, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

// panelBody is the body of a panel save.
type panelBody struct {
	Name    string            `json:"name"`
	Widgets []PanelWidgetJSON `json:"widgets"`
}

// checkPanel validates a panel the admin saves and fills in what the hub
// decides: widget IDs, action IDs and classes. Every entity must exist, and
// every action must be one its widget's kind offers, of class read or safe,
// and admit guests.
func (a *api) checkPanel(ctx context.Context, b panelBody) (panelBody, error) {
	b.Name = strings.TrimSpace(b.Name)
	if b.Name == "" || len([]rune(b.Name)) > maxPanelName {
		return b, fmt.Errorf("%w: a name of 1 to %d characters is required", errBadPanel, maxPanelName)
	}
	if len(b.Widgets) > maxPanelWidgets {
		return b, fmt.Errorf("%w: at most %d widgets", errBadPanel, maxPanelWidgets)
	}
	if b.Widgets == nil {
		b.Widgets = []PanelWidgetJSON{}
	}
	seen := map[string]bool{}
	for i := range b.Widgets {
		w := &b.Widgets[i]
		offered, ok := panelActions[w.Kind]
		if !ok {
			return b, fmt.Errorf("%w: widget %d: unknown kind %q (want device)", errBadPanel, i+1, w.Kind)
		}
		if _, err := a.store.Devices().Get(ctx, w.Entity); errors.Is(err, store.ErrNotFound) {
			return b, fmt.Errorf("%w: widget %d: no such device %q", errBadPanel, i+1, w.Entity)
		} else if err != nil {
			return b, err
		}
		if !widgetIDPattern().MatchString(w.ID) || seen[w.ID] {
			w.ID = strings.ToLower(rand.Text())
		}
		seen[w.ID] = true
		if len(w.Actions) > maxWidgetActions {
			return b, fmt.Errorf("%w: widget %d: at most %d actions", errBadPanel, i+1, maxWidgetActions)
		}
		if w.Actions == nil {
			w.Actions = []PanelActionJSON{}
		}
		ids := map[string]bool{}
		for j := range w.Actions {
			act := &w.Actions[j]
			action := policy.Action(act.Action)
			class, known := policy.ClassOf(action)
			if known && class == policy.Dangerous {
				return b, fmt.Errorf("%w: widget %d: %s is dangerous", errDangerousAction, i+1, action)
			}
			if !known || !slices.Contains(offered, action) || !policy.Admits(action, policy.ActorGuest) {
				return b, fmt.Errorf("%w: widget %d: %q is not an action a %s widget can allow", errBadPanel, i+1, act.Action, w.Kind)
			}
			if action == policy.DeviceRestart && !validService(act.Service) {
				return b, fmt.Errorf("%w: widget %d: a restart needs a service as manager:name, manager one of %s",
					errBadPanel, i+1, strings.Join(serviceManagers, ", "))
			}
			act.Class, act.ID = string(class), act.Action+":"+act.Service
			if ids[act.ID] {
				return b, fmt.Errorf("%w: widget %d lists %s twice", errBadPanel, i+1, act.ID)
			}
			ids[act.ID] = true
		}
	}
	return b, nil
}

// decodeWidgets parses the widgets a panel stores.
func decodeWidgets(p store.Panel) ([]PanelWidgetJSON, error) {
	var ws []PanelWidgetJSON
	if err := json.Unmarshal([]byte(p.Widgets), &ws); err != nil {
		return nil, fmt.Errorf("panel %s: decode widgets: %w", p.ID, err)
	}
	return ws, nil
}

func panelLinkJSON(l store.PanelLink, now time.Time) PanelLinkJSON {
	out := PanelLinkJSON{ID: l.ID, CreatedAt: l.CreatedAt, Status: "active"}
	if !l.ExpiresAt.IsZero() {
		exp := l.ExpiresAt
		out.ExpiresAt = &exp
		if !now.Before(exp) {
			out.Status = "expired"
		}
	}
	if !l.RevokedAt.IsZero() {
		rev := l.RevokedAt
		out.RevokedAt, out.Status = &rev, "revoked"
	}
	return out
}

func (a *api) panelJSON(p store.Panel, links []store.PanelLink) (PanelJSON, error) {
	ws, err := decodeWidgets(p)
	if err != nil {
		return PanelJSON{}, err
	}
	out := PanelJSON{ID: p.ID, Name: p.Name, Widgets: ws, Links: []PanelLinkJSON{}, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
	now := a.now()
	for _, l := range links {
		if l.PanelID == p.ID {
			out.Links = append(out.Links, panelLinkJSON(l, now))
		}
	}
	return out, nil
}

func (a *api) listPanels(w http.ResponseWriter, r *http.Request) {
	ps, err := a.store.Panels().List(r.Context())
	if err != nil {
		a.writePanelError(w, r, "list panels", err)
		return
	}
	links, err := a.store.Panels().Links(r.Context())
	if err != nil {
		a.writePanelError(w, r, "list panels", err)
		return
	}
	out := struct {
		Panels []PanelJSON `json:"panels"`
	}{Panels: make([]PanelJSON, 0, len(ps))}
	for _, p := range ps {
		pj, err := a.panelJSON(p, links)
		if err != nil {
			a.writePanelError(w, r, "list panels", err)
			return
		}
		out.Panels = append(out.Panels, pj)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) getPanel(w http.ResponseWriter, r *http.Request) {
	a.writePanel(w, r, http.StatusOK, r.PathValue("id"))
}

// writePanel answers with panel id and its links.
func (a *api) writePanel(w http.ResponseWriter, r *http.Request, status int, id string) {
	p, err := a.store.Panels().Get(r.Context(), id)
	if err != nil {
		a.writePanelError(w, r, "get panel", err)
		return
	}
	links, err := a.store.Panels().Links(r.Context())
	if err != nil {
		a.writePanelError(w, r, "get panel", err)
		return
	}
	pj, err := a.panelJSON(p, links)
	if err != nil {
		a.writePanelError(w, r, "get panel", err)
		return
	}
	writeJSON(w, status, pj)
}

// readPanelBody decodes and checks a panel save; it answers and returns
// false when the body is not one.
func (a *api) readPanelBody(w http.ResponseWriter, r *http.Request) (panelBody, string, bool) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return panelBody{}, "", false
	}
	var b panelBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPanelBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"name": "...", "widgets": [...]}`)
		return panelBody{}, "", false
	}
	b, err := a.checkPanel(r.Context(), b)
	if err != nil {
		a.writePanelError(w, r, "check panel", err)
		return panelBody{}, "", false
	}
	widgets, err := json.Marshal(b.Widgets)
	if err != nil {
		a.writePanelError(w, r, "encode panel", err)
		return panelBody{}, "", false
	}
	return b, string(widgets), true
}

// panelDetail is what the audit log shows of a saved panel: the entities
// and the actions it allows guests, never a secret.
func panelDetail(b panelBody) map[string]any {
	widgets := make([]map[string]any, 0, len(b.Widgets))
	for _, w := range b.Widgets {
		acts := make([]string, 0, len(w.Actions))
		for _, act := range w.Actions {
			acts = append(acts, act.ID)
		}
		widgets = append(widgets, map[string]any{"kind": w.Kind, "entity": w.Entity, "actions": acts})
	}
	return map[string]any{"name": b.Name, "widgets": widgets}
}

func (a *api) createPanel(w http.ResponseWriter, r *http.Request) {
	b, widgets, ok := a.readPanelBody(w, r)
	if !ok {
		return
	}
	id := strings.ToLower(rand.Text())
	err := a.policy.Do(r.Context(), policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.PanelSave, Target: id, Detail: panelDetail(b),
	}, func(ctx context.Context) error {
		return a.store.Panels().Create(ctx, store.Panel{ID: id, Name: b.Name, Widgets: widgets, CreatedAt: a.now()})
	})
	if err != nil {
		a.writePanelError(w, r, "create panel", err)
		return
	}
	a.writePanel(w, r, http.StatusCreated, id)
}

func (a *api) updatePanel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	b, widgets, ok := a.readPanelBody(w, r)
	if !ok {
		return
	}
	err := a.policy.Do(r.Context(), policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.PanelSave, Target: id, Detail: panelDetail(b),
	}, func(ctx context.Context) error {
		return a.store.Panels().Update(ctx, store.Panel{ID: id, Name: b.Name, Widgets: widgets}, a.now())
	})
	if err != nil {
		a.writePanelError(w, r, "update panel", err)
		return
	}
	a.guestStreams.recheck()
	a.writePanel(w, r, http.StatusOK, id)
}

func (a *api) deletePanel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx, reach := store.WithReach(r.Context())
	err := a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.PanelDelete, Target: id,
	}, func(ctx context.Context) error { return a.store.Panels().Delete(ctx, id) })
	if err != nil {
		a.writePanelError(w, r, "delete panel", err)
		return
	}
	a.guestStreams.recheck()
	writeReach(w, *reach)
}

// maxPanelLinkTTL bounds a share link's expiry; none at all means never.
const maxPanelLinkTTL = 10 * 365 * 24 * time.Hour

// createPanelLink makes a share link of a panel. Its secret is in the
// answer and nowhere else: the store keeps its hash, the audit log its ID.
func (a *api) createPanelLink(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		// ExpiresIn is a Go duration, as "24h"; empty for a link that never
		// expires.
		ExpiresIn string `json:"expires_in"`
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", `body must be {"expires_in": "24h"} or empty`)
			return
		}
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	// The link's id is derived from its secret, the link's unique key.
	secret := rand.Text()
	link := store.PanelLink{ID: store.PanelLinkID(secret), PanelID: id, CreatedAt: now}
	if body.ExpiresIn != "" {
		ttl, err := time.ParseDuration(body.ExpiresIn)
		if err != nil || ttl <= 0 || ttl > maxPanelLinkTTL {
			writeError(w, http.StatusBadRequest, "bad_request", "expires_in must be a positive duration, as 24h or 720h")
			return
		}
		link.ExpiresAt = now.Add(ttl)
	}
	detail := map[string]any{"link": link.ID}
	if !link.ExpiresAt.IsZero() {
		detail["expires_at"] = link.ExpiresAt
	}
	err := a.policy.Do(r.Context(), policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.PanelLinkCreate, Target: id, Detail: detail,
	}, func(ctx context.Context) error { return a.store.Panels().CreateLink(ctx, link, secret) })
	if err != nil {
		a.writePanelError(w, r, "create panel link", err)
		return
	}
	writeJSON(w, http.StatusCreated, CreatedPanelLinkJSON{
		Link: panelLinkJSON(link, now), Token: secret, Path: panelLinkPath + secret,
	})
}

func (a *api) revokePanelLink(w http.ResponseWriter, r *http.Request) {
	id, link := r.PathValue("id"), r.PathValue("link")
	ctx, reach := store.WithReach(r.Context())
	err := a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.PanelLinkRevoke, Target: id,
		Detail: map[string]any{"link": link},
	}, func(ctx context.Context) error { return a.store.Panels().RevokeLink(ctx, id, link, a.now()) })
	if err != nil {
		a.writePanelError(w, r, "revoke panel link", err)
		return
	}
	a.guestStreams.recheck()
	writeReach(w, *reach)
}

// writePanelError answers a failed panel request of the admin.
func (a *api) writePanelError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, errDangerousAction):
		writeError(w, http.StatusBadRequest, "dangerous_action", err.Error())
	case errors.Is(err, errBadPanel):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such panel or link")
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, store.ErrSchemaTooOld):
		writeError(w, http.StatusConflict, "schema_too_old",
			"the hub cluster's database predates panels: upgrade every hub of the cluster first")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(r.Context(), op, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "panel request failed")
	}
}
