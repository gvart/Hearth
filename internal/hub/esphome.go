// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"

	"github.com/gvart/hearth/internal/integrations/esphome"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// maxESPHomeBody bounds POST /esphome/devices: an address and a key.
const maxESPHomeBody = 4 << 10

// esphomeRoutes registers the ESPHome API, behind the admin session. Without
// a manager there are no routes.
func (a *api) esphomeRoutes(mux *http.ServeMux) {
	if a.esphome == nil {
		return
	}
	mux.Handle("GET /api/v1/esphome/devices", a.auth(a.listESPHomeDevices))
	mux.Handle("POST /api/v1/esphome/devices", a.auth(a.addESPHomeDevice))
	mux.Handle("GET /api/v1/esphome/devices/{id}", a.auth(a.getESPHomeDevice))
	mux.Handle("DELETE /api/v1/esphome/devices/{id}", a.auth(a.removeESPHomeDevice))
	mux.Handle("POST /api/v1/esphome/devices/{id}/call", a.auth(a.esphomeCall))
}

func (a *api) listESPHomeDevices(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Devices []esphome.DeviceInfo `json:"devices"`
	}{Devices: a.esphome.Devices()})
}

func (a *api) getESPHomeDevice(w http.ResponseWriter, r *http.Request) {
	snap, err := a.esphome.Snapshot(r.PathValue("id"))
	if err != nil {
		a.writeESPHomeError(w, r, "get esphome device", err)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (a *api) addESPHomeDevice(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var req esphome.AddRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxESPHomeBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"name": "...", "address": "...", "key": "...", "control": false}`)
		return
	}
	info, err := a.esphome.Add(r.Context(), remoteHost(r), req)
	if err != nil {
		a.writeESPHomeError(w, r, "add esphome device", err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

func (a *api) removeESPHomeDevice(w http.ResponseWriter, r *http.Request) {
	if err := a.esphome.Remove(r.Context(), remoteHost(r), r.PathValue("id")); err != nil {
		a.writeESPHomeError(w, r, "remove esphome device", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// esphomeCall turns a switch on or off or presses a button. A call policy
// holds for approval answers once it is decided.
func (a *api) esphomeCall(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var req esphome.CallRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be a call: {"key": 123, "action": "on"}`)
		return
	}
	res, err := a.esphome.Call(r.Context(), policy.ActorWeb, remoteHost(r), r.PathValue("id"), req)
	if err != nil {
		a.writeESPHomeError(w, r, "esphome call", err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// writeESPHomeError answers a failed ESPHome API call. No error carries the
// key: the manager's never quote it.
func (a *api) writeESPHomeError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, esphome.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such device")
	case errors.Is(err, esphome.ErrEntityNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such entity on this device")
	case errors.Is(err, esphome.ErrBadConnection), errors.Is(err, esphome.ErrBadName), errors.Is(err, esphome.ErrBadAction):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, esphome.ErrNameTaken):
		writeError(w, http.StatusConflict, "conflict", "a device with that name exists")
	case errors.Is(err, esphome.ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, "unavailable", err.Error())
	case errors.Is(err, store.ErrSchemaTooOld):
		writeError(w, http.StatusConflict, "schema_too_old",
			"the hub cluster's database predates ESPHome devices: upgrade every hub of the cluster first")
	case errors.Is(err, esphome.ErrReadOnly):
		writeError(w, http.StatusForbidden, "read_only",
			"the device was adopted read-only: remove it and adopt it again with calls allowed")
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(r.Context(), op, "err", err)
		writeError(w, http.StatusBadGateway, "esphome_error", err.Error())
	}
}
