// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestWriteOutcome: a write that was sent and not answered may have happened.
func TestWriteOutcome(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reset":
			panic(http.ErrAbortHandler) // resets the stream, having read the request
		case "/hang":
			<-r.Context().Done()
		case "/refuse":
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := &url.URL{Scheme: "https", Host: ln.Addr().String()}
	_ = ln.Close()

	for _, tc := range []struct {
		name, method, path string
		base               *url.URL
		uncertain          bool
	}{
		{"a patch whose stream was reset", http.MethodPatch, "/reset", base, true},
		{"a delete whose stream was reset", http.MethodDelete, "/reset", base, true},
		{"an eviction whose stream was reset", http.MethodPost, "/reset", base, true},
		{"a patch that timed out", http.MethodPatch, "/hang", base, true},
		{"a patch the API server refused", http.MethodPatch, "/refuse", base, false},
		{"a patch that could not connect", http.MethodPatch, "/x", closed, false},
		{"a read whose stream was reset", http.MethodGet, "/reset", base, false},
		{"a read that timed out", http.MethodGet, "/hang", base, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			c := &apiClient{base: tc.base, http: srv.Client()}
			resp, err := c.do(ctx, tc.method, tc.path, nil, "", nil)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatal("the request succeeded")
			}
			if got := errors.Is(err, ErrWriteOutcomeUnknown); got != tc.uncertain {
				t.Errorf("do = %v: uncertain %v, want %v", err, got, tc.uncertain)
			}
		})
	}
}
