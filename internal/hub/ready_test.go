// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

func TestAPIWaitsUntilCaughtUp(t *testing.T) {
	st := newTestStore(t)
	log := slog.New(slog.DiscardHandler)
	ready := make(chan struct{})
	a := newAPI(Config{Store: st, Policy: policy.New(st.Audit()), Log: log, Ready: ready})
	a.readyWait = 100 * time.Millisecond
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	get := func(path string) (int, string) {
		t.Helper()
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// Still catching up: the API answers 503 after a short wait.
	start := time.Now()
	if code, body := get("/api/v1/devices"); code != http.StatusServiceUnavailable || !strings.Contains(body, "catching_up") {
		t.Fatalf("before ready: %d %s", code, body)
	}
	if waited := time.Since(start); waited < a.readyWait {
		t.Errorf("answered after %v, want a wait of %v first", waited, a.readyWait)
	}
	// The UI itself is served at once.
	if code, _ := get("/"); code != http.StatusOK {
		t.Errorf("UI before ready: %d", code)
	}

	// A request waiting when the hub catches up is served normally.
	go func() {
		time.Sleep(30 * time.Millisecond)
		close(ready)
	}()
	if code, body := get("/api/v1/devices"); code != http.StatusUnauthorized {
		t.Fatalf("after ready: %d %s, want the usual 401 without a session", code, body)
	}
}
