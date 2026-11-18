// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"net/http"
)

// configDrift serves the comparison of the cluster's per-hub configuration:
// which items differ on which hubs, never digests or contents. A standalone
// hub has nothing to compare.
func (a *api) configDrift(w http.ResponseWriter, r *http.Request) {
	if a.drift == nil {
		writeJSON(w, http.StatusOK, map[string][]any{"hubs": {}, "items": {}})
		return
	}
	report, err := a.drift(r.Context())
	if err != nil {
		a.log.ErrorContext(r.Context(), "compare the hubs' configuration", "err", err)
		writeError(w, http.StatusServiceUnavailable, "cluster_unavailable", "cannot compare the hubs' configuration")
		return
	}
	writeJSON(w, http.StatusOK, report)
}
