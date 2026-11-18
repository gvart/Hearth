// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// maxKubeconfigBody bounds POST /kube/clusters: a kubeconfig with inline
// certificates is a few KiB.
const maxKubeconfigBody = 256 << 10

// kubeRoutes registers the Kubernetes API, behind the admin session. Without
// a manager there are no routes, and /kube/... answers 404 like any unknown
// endpoint.
func (a *api) kubeRoutes(mux *http.ServeMux) {
	if a.kube == nil {
		return
	}
	mux.Handle("GET /api/v1/kube/clusters", a.auth(a.listKubeClusters))
	mux.Handle("POST /api/v1/kube/clusters", a.auth(a.addKubeCluster))
	mux.Handle("GET /api/v1/kube/clusters/{id}", a.auth(a.getKubeCluster))
	mux.Handle("DELETE /api/v1/kube/clusters/{id}", a.auth(a.removeKubeCluster))
	mux.Handle("GET /api/v1/kube/clusters/{id}/pods/{namespace}/{pod}/logs", a.auth(a.kubePodLogs))
	mux.Handle("POST /api/v1/kube/clusters/{id}/actions", a.auth(a.kubeAction))
}

func (a *api) listKubeClusters(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Clusters []kubernetes.ClusterInfo `json:"clusters"`
	}{Clusters: a.kube.Clusters()})
}

func (a *api) getKubeCluster(w http.ResponseWriter, r *http.Request) {
	snap, err := a.kube.Snapshot(r.Context(), r.PathValue("id"))
	if err != nil {
		a.writeKubeError(w, r, "get kube cluster", err)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (a *api) addKubeCluster(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var body struct {
		Name       string `json:"name"`
		Kubeconfig string `json:"kubeconfig"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxKubeconfigBody)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"name": "...", "kubeconfig": "..."}`)
		return
	}
	info, err := a.kube.Add(r.Context(), remoteHost(r), body.Name, []byte(body.Kubeconfig))
	if err != nil {
		a.writeKubeError(w, r, "add kube cluster", err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

func (a *api) removeKubeCluster(w http.ResponseWriter, r *http.Request) {
	if err := a.kube.Remove(r.Context(), remoteHost(r), r.PathValue("id")); err != nil {
		a.writeKubeError(w, r, "remove kube cluster", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) kubePodLogs(w http.ResponseWriter, r *http.Request) {
	tail := 500
	if s := r.URL.Query().Get("tail"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "bad_request", "tail must be a positive number of lines")
			return
		}
		tail = n
	}
	logs, err := a.kube.Logs(r.Context(), policy.ActorWeb, remoteHost(r), r.PathValue("id"),
		r.PathValue("namespace"), r.PathValue("pod"), r.URL.Query().Get("container"), tail)
	if err != nil {
		a.writeKubeError(w, r, "pod logs", err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Logs string `json:"logs"`
	}{Logs: logs})
}

// kubeAction plans a Kubernetes action and, unless it is a dry run, carries
// it out. A drain answers when its pods are gone or its timeout passed.
func (a *api) kubeAction(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var req kubernetes.ActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be an action: {"action": "...", "name": "...", ...}`)
		return
	}
	res, err := a.kube.Act(r.Context(), policy.ActorWeb, remoteHost(r), r.PathValue("id"), req)
	if err != nil {
		a.writeKubeError(w, r, "kube action", err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// writeKubeError answers a failed Kubernetes API call.
func (a *api) writeKubeError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, kubernetes.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such cluster")
	case errors.Is(err, kubernetes.ErrPodNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such pod or container")
	case errors.Is(err, kubernetes.ErrObjectNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, kubernetes.ErrInvalidKubeconfig), errors.Is(err, kubernetes.ErrBadName), errors.Is(err, kubernetes.ErrBadAction):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, kubernetes.ErrNameTaken):
		writeError(w, http.StatusConflict, "conflict", "a cluster with that name exists")
	case errors.Is(err, store.ErrSchemaTooOld):
		writeError(w, http.StatusConflict, "schema_too_old",
			"the hub cluster's database predates Kubernetes clusters: run `hearth cluster migrate` first")
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(r.Context(), op, "err", err)
		writeError(w, http.StatusBadGateway, "kube_error", err.Error())
	}
}
