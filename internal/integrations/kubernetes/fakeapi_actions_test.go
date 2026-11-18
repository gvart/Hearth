// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
)

// The fake API server's objects, for the Kubernetes actions: GET, PATCH
// and DELETE of one object, a PATCH of a workload's scale and a pod's
// eviction. Objects are those its lists serve, so the watchers see every
// change an action makes.

// objectPath maps the path of one object to the list path it is kept under
// and its key there, and names its subresource ("scale", "eviction").
func objectPath(p string) (list, key, sub string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	switch {
	case len(parts) == 4 && parts[0] == "api" && parts[2] == "nodes":
		return "/api/v1/nodes", "/" + parts[3], "", true
	case len(parts) >= 6 && parts[0] == "api" && parts[2] == "namespaces" && parts[4] == "pods":
		return "/api/v1/pods", parts[3] + "/" + parts[5], strings.Join(parts[6:], "/"), true
	case len(parts) >= 7 && parts[0] == "apis" && parts[1] == "apps" && parts[3] == "namespaces":
		return "/apis/apps/v1/" + parts[5], parts[4] + "/" + parts[6], strings.Join(parts[7:], "/"), true
	}
	return "", "", "", false
}

// mergeInto applies a JSON merge patch (RFC 7386) to o.
func mergeInto(o, patch map[string]any) {
	for k, v := range patch {
		pv, isMap := v.(map[string]any)
		ov, _ := o[k].(map[string]any)
		switch {
		case v == nil:
			delete(o, k)
		case isMap && ov != nil:
			mergeInto(ov, pv)
		case isMap:
			o[k] = map[string]any{}
			mergeInto(o[k].(map[string]any), pv)
		default:
			o[k] = v
		}
	}
}

func deepCopy(o map[string]any) map[string]any {
	b, _ := json.Marshal(o)
	var cp map[string]any
	_ = json.Unmarshal(b, &cp)
	return cp
}

// serveObject serves a request on one object and reports whether the path
// was one.
func (f *fakeAPI) serveObject(w http.ResponseWriter, r *http.Request) bool {
	list, key, sub, ok := objectPath(r.URL.Path)
	if !ok {
		return false
	}
	f.mu.Lock()
	o, found := f.objs[list][key]
	if found {
		o = deepCopy(o)
	}
	refuse := f.refuse[key]
	if r.Method == http.MethodPost && sub == "eviction" && refuse > 0 {
		f.refuse[key]--
	}
	f.mu.Unlock()
	if !found {
		writeStatus(w, http.StatusNotFound, "not found")
		return true
	}
	switch {
	case r.Method == http.MethodGet && sub == "":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(o)
	case r.Method == http.MethodPatch && (sub == "" || sub == "scale"):
		var patch map[string]any
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			writeStatus(w, http.StatusBadRequest, err.Error())
			return true
		}
		mergeInto(o, patch)
		f.put(list, o)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(o)
	case r.Method == http.MethodDelete && sub == "":
		f.del(list, o)
		writeStatus(w, http.StatusOK, "")
	case r.Method == http.MethodPost && sub == "eviction":
		if refuse > 0 {
			writeStatus(w, http.StatusTooManyRequests, "Cannot evict pod as it would violate the pod's disruption budget.")
			return true
		}
		f.del(list, o)
		writeStatus(w, http.StatusCreated, "")
	default:
		writeStatus(w, http.StatusMethodNotAllowed, "method not allowed")
	}
	return true
}

// actionRequests returns the requests of the Kubernetes actions so far.
func (f *fakeAPI) actionRequests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.actions)
}

// object returns a copy of the object at key of list path, nil if none.
func (f *fakeAPI) object(list, key string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objs[list][key]
	if !ok {
		return nil
	}
	return deepCopy(o)
}
