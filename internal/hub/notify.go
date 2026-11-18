// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"net/http"

	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// notifyRoutes registers the notification channels API, behind the admin
// session. Channels are listed by name and type only: their addresses and
// credentials never leave the hub's channels file.
func (a *api) notifyRoutes(mux *http.ServeMux) {
	if a.notify == nil {
		return
	}
	mux.Handle("GET /api/v1/notify/channels", a.auth(a.listNotifyChannels))
	mux.Handle("POST /api/v1/notify/channels/{name}/test", a.auth(a.testNotifyChannel))
}

func (a *api) listNotifyChannels(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Channels []notify.ChannelInfo `json:"channels"`
	}{Channels: a.notify.Channels()})
}

// testNotifyChannel sends a test message to a channel, through policy.
func (a *api) testNotifyChannel(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !a.notify.Has(name) {
		writeError(w, http.StatusNotFound, "not_found", "no such channel")
		return
	}
	err := a.policy.Do(r.Context(), policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.NotifyTest, Target: name,
	}, func(ctx context.Context) error {
		return a.notify.Send(ctx, name, "Hearth", "Test notification from Hearth: this channel works.")
	})
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		// The error names the channel and the provider's reason only.
		writeError(w, http.StatusBadGateway, "notify_error", err.Error())
	}
}
