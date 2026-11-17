// SPDX-License-Identifier: AGPL-3.0-only

package webui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestHandler(t *testing.T) {
	t.Parallel()

	built := fstest.MapFS{
		"index.html":    {Data: []byte("<html>app</html>")},
		"assets/app.js": {Data: []byte("console.log('hi')")},
	}
	empty := fstest.MapFS{".gitkeep": {Data: nil}}

	tests := []struct {
		name       string
		fsys       fstest.MapFS
		path       string
		wantStatus int
		wantBody   string
	}{
		{name: "root serves index", fsys: built, path: "/", wantStatus: http.StatusOK, wantBody: "app"},
		{name: "asset served", fsys: built, path: "/assets/app.js", wantStatus: http.StatusOK, wantBody: "console.log"},
		{name: "client route falls back to index", fsys: built, path: "/devices/42", wantStatus: http.StatusOK, wantBody: "app"},
		{name: "client route with dots falls back to index", fsys: built, path: "/devices/192.168.1.10", wantStatus: http.StatusOK, wantBody: "app"},
		{name: "client route with hostname falls back to index", fsys: built, path: "/devices/nas.lan", wantStatus: http.StatusOK, wantBody: "app"},
		{name: "missing asset is 404", fsys: built, path: "/assets/missing.js", wantStatus: http.StatusNotFound},
		{name: "no directory listing", fsys: built, path: "/assets/", wantStatus: http.StatusNotFound},
		{name: "no directory listing without slash", fsys: built, path: "/assets", wantStatus: http.StatusNotFound},
		{name: "traversal rejected", fsys: built, path: "/../../etc/passwd", wantStatus: http.StatusBadRequest},
		{name: "no build serves fallback", fsys: empty, path: "/", wantStatus: http.StatusOK, wantBody: "built without the web UI"},
		{name: "no build fallback on any path", fsys: empty, path: "/devices", wantStatus: http.StatusOK, wantBody: "built without the web UI"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			newHandler(tt.fsys).ServeHTTP(rec, req)

			res := rec.Result()
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if res.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", res.StatusCode, tt.wantStatus)
			}
			if !strings.Contains(string(body), tt.wantBody) {
				t.Errorf("body %q does not contain %q", body, tt.wantBody)
			}
		})
	}
}

func TestEmbeddedHandlerServes(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !Available() && !strings.Contains(rec.Body.String(), "built without the web UI") {
		t.Errorf("expected fallback page when UI is not embedded, got %q", rec.Body.String())
	}
}
