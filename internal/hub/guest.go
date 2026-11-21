// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// The guest API.
//
// A share link's secret is the only credential of a guest, for one panel:
// 130 random bits, stored hashed. A guest can read that panel's entities, as
// a reduced view, and take the actions its widgets allow, naming them by the
// IDs the hub gave them: the device and service come from the stored panel,
// never from the guest. Each action goes through policy as ActorGuest,
// panel/<panel id>, capped at the safe class, and is audited. An unknown,
// revoked or expired link, or one whose panel is gone, is a 404 like any
// other, and the secret is never a session or a bearer token anywhere else.

const (
	// guestActionBurst and guestActionEvery set the per-link rate of guest
	// actions: a burst of guestActionBurst, then one more every
	// guestActionEvery.
	guestActionBurst = 5
	guestActionEvery = 10 * time.Second
	// guestReadBurst and guestReadEvery set the per-link rate of panel
	// reads: a page refetches only when told something changed.
	guestReadBurst = 30
	guestReadEvery = time.Second
	// maxGuestInflight bounds the actions of one link running or held for
	// approval at once, and maxGuestHeld those held: each hold may notify
	// the operator.
	maxGuestInflight = 2
	maxGuestHeld     = 1
	// maxGuestStreamsPerLink bounds the event streams of one link, and
	// maxGuestStreams those of all links.
	maxGuestStreamsPerLink = 6
	maxGuestStreams        = 64
	// guestActionTimeout is how long a guest's restart may take.
	guestActionTimeout = time.Minute
	// guestAnswerGrace is how long the hub waits past the timeout for the
	// agent's answer.
	guestAnswerGrace = 15 * time.Second
)

// agentRunner runs exec requests on devices' agents: *Agents.
type agentRunner interface {
	Check(ctx context.Context, device string, req *agentv1.ExecRequest) error
	Exec(ctx context.Context, device string, req *agentv1.ExecRequest) (*agentv1.ExecResult, error)
}

// GuestActionJSON is an action a guest may take on a widget.
type GuestActionJSON struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// GuestWidgetJSON is what a guest sees of a widget: the entity's name and
// state, never its facts, addresses or labels.
type GuestWidgetJSON struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
	// Status is online, offline or unknown; unknown for a device that is
	// gone.
	Status   string            `json:"status"`
	LastSeen *time.Time        `json:"last_seen"`
	Actions  []GuestActionJSON `json:"actions"`
}

// GuestPanelJSON is a panel as its guests see it.
type GuestPanelJSON struct {
	Name    string            `json:"name"`
	Widgets []GuestWidgetJSON `json:"widgets"`
}

// guestRoutes registers the guest API and the share link page.
func (a *api) guestRoutes(mux *http.ServeMux, ui http.Handler) {
	mux.HandleFunc("GET /api/v1/guest/{token}", a.guestPanel)
	mux.HandleFunc("GET /api/v1/guest/{token}/events", a.guestEvents)
	mux.HandleFunc("POST /api/v1/guest/{token}/actions", a.guestAction)
	mux.Handle("GET "+panelLinkPath+"{token}", a.guestPage(ui))
}

// guestInflight counts the actions of each link running or held.
type guestInflight struct {
	mu sync.Mutex
	n  map[string]int
}

// acquire takes a slot for link, unless it has limit already.
func (g *guestInflight) acquire(link string, limit int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n == nil {
		g.n = map[string]int{}
	}
	if g.n[link] >= limit {
		return false
	}
	g.n[link]++
	return true
}

func (g *guestInflight) release(link string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n[link]--; g.n[link] <= 0 {
		delete(g.n, link)
	}
}

// guestStreams counts the open guest event streams, per link and in all,
// and wakes them to check their link again when a panel or link changes.
type guestStreams struct {
	mu    sync.Mutex
	n     map[string]int
	total int
	wake  map[chan struct{}]struct{}
}

// open takes a stream slot for link and returns its wake channel and the
// func that frees the slot, or false when link or the hub has no slot left.
func (g *guestStreams) open(link string) (<-chan struct{}, func(), bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.total >= maxGuestStreams || g.n[link] >= maxGuestStreamsPerLink {
		return nil, nil, false
	}
	if g.n == nil {
		g.n, g.wake = map[string]int{}, map[chan struct{}]struct{}{}
	}
	g.n[link]++
	g.total++
	ch := make(chan struct{}, 1)
	g.wake[ch] = struct{}{}
	return ch, func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		delete(g.wake, ch)
		g.total--
		if g.n[link]--; g.n[link] <= 0 {
			delete(g.n, link)
		}
	}, true
}

// recheck wakes every stream to check its link and panel again: one was
// changed, revoked or deleted on this hub.
func (g *guestStreams) recheck() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for ch := range g.wake {
		select {
		case ch <- struct{}{}:
		default: // it has a wake pending already
		}
	}
}

// guestLink finds the panel of the request's share link and its widgets. It
// answers 404 for a link that is unknown, revoked or expired, or whose
// panel is gone, and returns false.
func (a *api) guestLink(w http.ResponseWriter, r *http.Request) (store.Panel, store.PanelLink, []PanelWidgetJSON, bool) {
	p, l, ws, err := a.checkGuestLink(r.Context(), r.PathValue("token"))
	if err != nil {
		a.writeGuestLinkError(w, r, err)
		return store.Panel{}, store.PanelLink{}, nil, false
	}
	return p, l, ws, true
}

func (a *api) checkGuestLink(ctx context.Context, token string) (store.Panel, store.PanelLink, []PanelWidgetJSON, error) {
	if token == "" {
		return store.Panel{}, store.PanelLink{}, nil, store.ErrNotFound
	}
	p, l, err := a.store.Panels().CheckLink(ctx, token, a.now())
	if err != nil {
		return store.Panel{}, store.PanelLink{}, nil, err
	}
	ws, err := decodeWidgets(p)
	if err != nil {
		return store.Panel{}, store.PanelLink{}, nil, err
	}
	return p, l, ws, nil
}

// isGuestLinkGone reports whether err means the link opens nothing.
func isGuestLinkGone(err error) bool {
	return errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrTokenRevoked) || errors.Is(err, store.ErrTokenExpired)
}

func (a *api) writeGuestLinkError(w http.ResponseWriter, r *http.Request, err error) {
	if isGuestLinkGone(err) {
		writeError(w, http.StatusNotFound, "not_found", "this panel link is invalid, revoked or expired")
		return
	}
	a.log.ErrorContext(r.Context(), "check panel link", "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "cannot open the panel")
}

// guestPage serves the web UI for a usable share link, and a plain 404
// otherwise.
func (a *api) guestPage(ui http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, _, err := a.checkGuestLink(r.Context(), r.PathValue("token")); err != nil {
			if !isGuestLinkGone(err) {
				a.log.ErrorContext(r.Context(), "check panel link", "err", err)
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintln(w, "This panel link is invalid, revoked or expired.")
			return
		}
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		ui.ServeHTTP(w, r)
	})
}

func (a *api) guestPanel(w http.ResponseWriter, r *http.Request) {
	p, l, ws, ok := a.guestLink(w, r)
	if !ok {
		return
	}
	if ok, wait := a.guestReads.allow(l.ID); !ok {
		writeRetry(w, http.StatusTooManyRequests, wait, "rate_limited", "too many requests; try again later")
		return
	}
	out := GuestPanelJSON{Name: p.Name, Widgets: make([]GuestWidgetJSON, 0, len(ws))}
	for _, wd := range ws {
		gw, err := a.guestWidget(r.Context(), wd)
		if err != nil {
			a.log.ErrorContext(r.Context(), "guest panel", "panel", p.ID, "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "cannot read the panel")
			return
		}
		out.Widgets = append(out.Widgets, gw)
	}
	writeJSON(w, http.StatusOK, out)
}

// guestWidget renders a widget for a guest.
func (a *api) guestWidget(ctx context.Context, wd PanelWidgetJSON) (GuestWidgetJSON, error) {
	out := GuestWidgetJSON{ID: wd.ID, Kind: wd.Kind, Status: store.StatusUnknown, Actions: []GuestActionJSON{}}
	for _, act := range wd.Actions {
		out.Actions = append(out.Actions, GuestActionJSON{ID: act.ID, Label: actionLabel(act)})
	}
	d, err := a.store.Devices().Get(ctx, wd.Entity)
	if errors.Is(err, store.ErrNotFound) {
		out.Name = "Removed device"
		return out, nil
	}
	if err != nil {
		return GuestWidgetJSON{}, err
	}
	out.Name, out.Status = d.Name, d.Status
	if !d.LastSeen.IsZero() {
		out.LastSeen = &d.LastSeen
	}
	return out, nil
}

// actionLabel is what a guest's button says.
func actionLabel(act PanelActionJSON) string {
	if policy.Action(act.Action) == policy.DeviceRestart {
		_, name, _ := strings.Cut(act.Service, ":")
		return "Restart " + name
	}
	return act.Action
}

// GuestActionResultJSON answers a guest action that ran.
type GuestActionResultJSON struct {
	OK bool `json:"ok"`
}

// guestAction takes an action a widget of the link's panel allows. The body
// names the widget and the action by their IDs; anything else is a 404.
func (a *api) guestAction(w http.ResponseWriter, r *http.Request) {
	p, l, ws, ok := a.guestLink(w, r)
	if !ok {
		return
	}
	// Before anything else: a guest probing for widgets and actions spends
	// its budget too.
	if ok, wait := a.guestActions.allow(l.ID); !ok {
		writeRetry(w, http.StatusTooManyRequests, wait, "rate_limited", "too many actions; try again later")
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var body struct {
		Widget string `json:"widget"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"widget": "...", "action": "..."}`)
		return
	}
	wd, act, found := findGuestAction(ws, body.Widget, body.Action)
	if !found {
		writeError(w, http.StatusNotFound, "not_found", "this panel has no such action")
		return
	}
	if !a.guestBusy.acquire(l.ID, maxGuestInflight) {
		writeError(w, http.StatusTooManyRequests, "busy", "an action of this panel is still running or waiting for approval")
		return
	}
	defer a.guestBusy.release(l.ID)

	err := a.runGuestAction(r.Context(), r.PathValue("token"), p, l, wd, act)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, GuestActionResultJSON{OK: true})
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "denied", "not allowed right now")
	case errors.Is(err, ErrAgentNotConnected):
		writeError(w, http.StatusServiceUnavailable, "device_offline", "the device is not connected")
	case errors.Is(err, errGuestHeld):
		writeError(w, http.StatusTooManyRequests, "pending", "an action of this panel is waiting for approval")
	case errors.Is(err, errGuestActionsOff):
		writeError(w, http.StatusServiceUnavailable, "unavailable", "this hub runs no actions")
	case r.Context().Err() != nil:
		return // the guest went away
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		// The audit log has the reason; the guest gets none of it.
		a.log.WarnContext(r.Context(), "guest action failed", "panel", p.ID, "link", l.ID, "action", act.ID, "err", err)
		writeError(w, http.StatusBadGateway, "action_failed", "the action failed")
	}
}

// findGuestAction finds action actionID of widget widgetID.
func findGuestAction(ws []PanelWidgetJSON, widgetID, actionID string) (PanelWidgetJSON, PanelActionJSON, bool) {
	for _, wd := range ws {
		if wd.ID != widgetID {
			continue
		}
		for _, act := range wd.Actions {
			if act.ID == actionID {
				return wd, act, true
			}
		}
	}
	return PanelWidgetJSON{}, PanelActionJSON{}, false
}

var (
	errGuestActionsOff = errors.New("this hub runs no agent actions")
	errGuestHeld       = errors.New("an action of this panel link is held for approval already")
)

// runGuestAction runs act on wd's entity through policy, as the panel's
// guest, whose link is token. The class is capped at safe whatever the
// stored panel says. A link has at most maxGuestHeld actions held for
// approval, and a held one runs only if, once approved, the link and the
// action are still there.
func (a *api) runGuestAction(ctx context.Context, token string, p store.Panel, l store.PanelLink, wd PanelWidgetJSON, act PanelActionJSON) error {
	action := policy.Action(act.Action)
	if action != policy.DeviceRestart || wd.Kind != widgetDevice {
		// checkPanel stores no other: refuse rather than guess.
		return fmt.Errorf("guest action %s on a %s widget: %w", action, wd.Kind, policy.ErrDenied)
	}
	if a.runner == nil {
		return errGuestActionsOff
	}
	manager, name, _ := strings.Cut(act.Service, ":")
	req := &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Restart{
		Restart: &agentv1.RestartService{Manager: manager, Name: name},
	}}
	device := wd.Entity
	preq := policy.Request{
		ActorKind: policy.ActorGuest, ActorID: "panel/" + p.ID, Action: action, Target: device,
		Detail:   map[string]any{"service": act.Service, "panel": p.ID, "link": l.ID, "widget": wd.ID},
		Precheck: func(ctx context.Context) error { return a.runner.Check(ctx, device, req) },
	}
	if decision, _ := a.policy.Check(preq); decision == policy.Confirm {
		if !a.guestHeld.acquire(l.ID, maxGuestHeld) {
			return errGuestHeld
		}
		defer a.guestHeld.release(l.ID)
	}
	return a.policy.Do(policy.WithScope(ctx, policy.Safe), preq, func(ctx context.Context) error {
		// Approval may come long after the request: the link may be revoked
		// or the panel changed by then.
		if err := a.stillOffered(ctx, token, p.ID, wd, act); err != nil {
			return err
		}
		req.Timeout = durationpb.New(guestActionTimeout)
		ctx, cancel := context.WithTimeout(ctx, guestActionTimeout+guestAnswerGrace)
		defer cancel()
		res, err := a.runner.Exec(ctx, device, req)
		if err != nil {
			return fmt.Errorf("restart %s: %w", act.Service, err)
		}
		if res.GetDenied() {
			return fmt.Errorf("restart %s on device %s: %w", act.Service, device, policy.ErrBeyondCeiling)
		}
		if res.GetError() != "" {
			return fmt.Errorf("restart %s on device %s failed (exit code %d): %s", act.Service, device, res.GetExitCode(), res.GetError())
		}
		return nil
	})
}

// stillOffered checks that token still opens panel panelID and that it
// still offers act on wd, as it did when the guest asked; it returns an
// error matching policy.ErrDenied when not.
func (a *api) stillOffered(ctx context.Context, token, panelID string, wd PanelWidgetJSON, act PanelActionJSON) error {
	p, _, ws, err := a.checkGuestLink(ctx, token)
	if isGuestLinkGone(err) {
		return fmt.Errorf("panel link no longer valid: %w", policy.ErrDenied)
	}
	if err != nil {
		return err
	}
	nwd, nact, found := findGuestAction(ws, wd.ID, act.ID)
	if p.ID != panelID || !found || nwd.Kind != wd.Kind || nwd.Entity != wd.Entity || nact != act {
		return fmt.Errorf("panel %s no longer offers this action: %w", panelID, policy.ErrDenied)
	}
	return nil
}

// guestEvents streams a bare "changed" event whenever a device on the
// link's panel changes, or the panel itself, so the page refetches the
// panel. The link is checked again on every event and keepalive, and when
// a panel or link changes on this hub: a revoked or expired link, or a
// deleted panel, ends the stream. A link has at most
// maxGuestStreamsPerLink streams open, and the hub maxGuestStreams.
func (a *api) guestEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.PathValue("token")
	p, l, ws, ok := a.guestLink(w, r)
	if !ok {
		return
	}
	wake, closeStream, ok := a.guestStreams.open(l.ID)
	if !ok {
		writeRetry(w, http.StatusTooManyRequests, a.keepalive, "too_many_streams", "too many open pages of this panel")
		return
	}
	defer closeStream()
	updated := p.UpdatedAt
	rc := http.NewResponseController(w)
	ch, unsubscribe := a.registry.SubscribeUI()
	defer unsubscribe()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprint(w, ": subscribed\n\n"); err != nil || rc.Flush() != nil {
		return
	}
	keepalive := time.NewTicker(a.keepalive)
	defer keepalive.Stop()
	for {
		var err error
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if ev.Hosts != nil || !onPanel(ws, ev.Device.ID) {
				continue
			}
			if _, _, ws, err = a.checkGuestLink(ctx, token); err != nil {
				return
			}
			_, err = fmt.Fprint(w, "event: changed\ndata: {}\n\n")
		case <-wake:
			if p, _, ws, err = a.checkGuestLink(ctx, token); err != nil {
				return
			}
			if p.UpdatedAt.Equal(updated) {
				continue
			}
			updated = p.UpdatedAt
			_, err = fmt.Fprint(w, "event: changed\ndata: {}\n\n")
		case <-keepalive.C:
			// A change on another hub of the cluster wakes no stream here.
			if p, _, ws, err = a.checkGuestLink(ctx, token); err != nil {
				return
			}
			if p.UpdatedAt.Equal(updated) {
				_, err = fmt.Fprint(w, ": keepalive\n\n")
			} else {
				updated = p.UpdatedAt
				_, err = fmt.Fprint(w, "event: changed\ndata: {}\n\n")
			}
		}
		if err != nil || rc.Flush() != nil {
			return
		}
	}
}

// onPanel reports whether device id is the entity of one of ws.
func onPanel(ws []PanelWidgetJSON, id string) bool {
	for _, wd := range ws {
		if wd.Kind == widgetDevice && wd.Entity == id {
			return true
		}
	}
	return false
}
