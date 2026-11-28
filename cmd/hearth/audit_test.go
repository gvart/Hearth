// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/store"
)

func TestAuditVerifyCmd(t *testing.T) {
	t.Setenv("HEARTH_ADMIN_PASSWORD", "pw")
	for _, tt := range []struct {
		name string
		rep  hub.AuditVerifyJSON
		want []string
		err  error
	}{
		{
			name: "ok",
			rep: hub.AuditVerifyJSON{OK: true, AuditReport: store.AuditReport{
				CanVerify: true, Entries: 12, Legacy: 2,
				Chains: []store.AuditChainReport{{Origin: "hub-a", Last: 10, Verified: 10}},
			}},
			want: []string{"12 entries: 2 legacy", "hub-a: entries 1-10, 10 verified: OK", "The audit log verifies."},
		},
		{
			name: "gaps",
			rep: hub.AuditVerifyJSON{AuditReport: store.AuditReport{
				CanVerify: true, Entries: 140, Unsealed: 1,
				Chains: []store.AuditChainReport{{
					Origin: "hub-a", Last: 140, Verified: 127, Missing: []store.AuditRange{{From: 120, To: 131}},
					Unverified: []int64{135}, Broken: []int64{136},
				}},
			}},
			want: []string{
				"hub-a: entries 1-140, 127 verified: NOT OK", "entries 120-131 from hub-a missing",
				"entry 135: its seal does not check", "entry 136: does not follow", "1 entries written since sealing started have no seal",
			},
			err: errAuditNotOK,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("POST /api/v1/login", func(w http.ResponseWriter, _ *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
				w.WriteHeader(http.StatusNoContent)
			})
			mux.HandleFunc("GET /api/v1/audit/verify", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(tt.rep)
			})
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			cmd := newAuditCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(io.Discard)
			cmd.SetIn(strings.NewReader(""))
			cmd.SetArgs([]string{"verify", "--hub-url", srv.URL})
			if err := cmd.ExecuteContext(t.Context()); !errors.Is(err, tt.err) {
				t.Fatalf("err = %v, want %v", err, tt.err)
			}
			for _, w := range tt.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output lacks %q:\n%s", w, out.String())
				}
			}
		})
	}
}
