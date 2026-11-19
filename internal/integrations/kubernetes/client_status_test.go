// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

// TestWriteStatusOutcome: a write the API server answered with a timeout may
// still complete. A definite refusal, and a read, did nothing.
func TestWriteStatusOutcome(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code, _ := strconv.Atoi(r.URL.Query().Get("code"))
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(status{Message: "the server says no", Reason: r.URL.Query().Get("reason"), Code: code})
	}))
	t.Cleanup(srv.Close)
	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method string
		code         int
		reason       string
		uncertain    bool
	}{
		{"a patch answered 504", http.MethodPatch, http.StatusGatewayTimeout, "", true},
		{"a post answered 504", http.MethodPost, http.StatusGatewayTimeout, "", true},
		{"a put answered 504", http.MethodPut, http.StatusGatewayTimeout, "", true},
		{"a delete answered 504", http.MethodDelete, http.StatusGatewayTimeout, "", true},
		{"a patch answered 500 ServerTimeout", http.MethodPatch, http.StatusInternalServerError, "ServerTimeout", true},
		{"a delete answered 500 ServerTimeout", http.MethodDelete, http.StatusInternalServerError, "ServerTimeout", true},
		{"a post answered 504 Timeout", http.MethodPost, http.StatusGatewayTimeout, "Timeout", true},
		{"a patch answered 500 Timeout", http.MethodPatch, http.StatusInternalServerError, "Timeout", true},
		{"a read answered 504", http.MethodGet, http.StatusGatewayTimeout, "", false},
		{"a read answered 500 ServerTimeout", http.MethodGet, http.StatusInternalServerError, "ServerTimeout", false},
		{"a patch answered 500 InternalError", http.MethodPatch, http.StatusInternalServerError, "InternalError", false},
		{"a patch answered 500", http.MethodPatch, http.StatusInternalServerError, "", false},
		{"a patch answered 400", http.MethodPatch, http.StatusBadRequest, "BadRequest", false},
		{"a patch answered 403", http.MethodPatch, http.StatusForbidden, "Forbidden", false},
		{"a delete answered 404", http.MethodDelete, http.StatusNotFound, "NotFound", false},
		{"a patch answered 409", http.MethodPatch, http.StatusConflict, "Conflict", false},
		{"a post answered 422", http.MethodPost, http.StatusUnprocessableEntity, "Invalid", false},
		{"a post answered 429", http.MethodPost, http.StatusTooManyRequests, "TooManyRequests", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &apiClient{base: base, http: srv.Client()}
			q := url.Values{"code": {strconv.Itoa(tc.code)}, "reason": {tc.reason}}
			resp, err := c.do(t.Context(), tc.method, "/x", q, "", nil)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatal("the request succeeded")
			}
			if got := errors.Is(err, ErrWriteOutcomeUnknown); got != tc.uncertain {
				t.Errorf("do = %v: uncertain %v, want %v", err, got, tc.uncertain)
			}
			if !hasCode(err, tc.code) {
				t.Errorf("do = %v, want the API error with code %d kept", err, tc.code)
			}
		})
	}
}
