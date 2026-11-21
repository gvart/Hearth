// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestConfigDriftAPI(t *testing.T) {
	const path = "/api/v1/cluster/config-drift"
	tests := []struct {
		name     string
		drift    func(context.Context) (any, error)
		wantCode int
		wantBody string
	}{
		{"standalone hub", nil, http.StatusOK, `{"hubs":[],"items":[]}` + "\n"},
		{
			"cluster",
			func(context.Context) (any, error) { return map[string]string{"state": "compared"}, nil },
			http.StatusOK, `{"state":"compared"}` + "\n",
		},
		{
			"comparison fails",
			func(context.Context) (any, error) { return nil, errors.New("no store") },
			http.StatusServiceUnavailable, "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newAPIFixture(t, true, func(c *Config) { c.ConfigDrift = tt.drift })
			if r := f.do(t, http.MethodGet, path, "", nil); r.StatusCode != http.StatusUnauthorized {
				t.Fatalf("unauthenticated = %d, want 401", r.StatusCode)
			}
			if err := f.st.Admin().CreateSession(t.Context(), "s", time.Now(), time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			r := f.do(t, http.MethodGet, path, "", testCookie("s"))
			if r.StatusCode != tt.wantCode {
				t.Fatalf("status = %d %s, want %d", r.StatusCode, r.body, tt.wantCode)
			}
			if tt.wantBody != "" && string(r.body) != tt.wantBody {
				t.Errorf("body = %s, want %s", r.body, tt.wantBody)
			}
		})
	}
}
