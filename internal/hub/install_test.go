// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gvart/hearth/deploy"
)

// installMux mirrors the hub's web mux: the installer routes next to a
// catch-all that stands in for the UI and API.
func installMux(assetsDir string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ui")
	})
	RegisterInstallRoutes(mux, assetsDir)
	return mux
}

// get serves one request and returns the recorded response.
func get(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, target, nil))
	return rec
}

func TestInstallScriptRoute(t *testing.T) {
	rec := get(t, installMux(""), http.MethodGet, "/install.sh")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/x-shellscript; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if rec.Body.String() != string(deploy.InstallScript) {
		t.Error("body is not the embedded deploy/install.sh")
	}

	rec = get(t, installMux(""), http.MethodHead, "/install.sh")
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD: status = %d, body length %d", rec.Code, rec.Body.Len())
	}
	if rec = get(t, installMux(""), http.MethodPost, "/install.sh"); rec.Body.String() == string(deploy.InstallScript) {
		t.Error("POST /install.sh must not serve the script")
	}
}

func TestInstallPowerShellRoute(t *testing.T) {
	rec := get(t, installMux(""), http.MethodGet, "/install.ps1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if rec.Body.String() != string(deploy.InstallPowerShell) || !strings.Contains(rec.Body.String(), "[CmdletBinding(") {
		t.Error("body is not the embedded deploy/install.ps1")
	}
	if rec = get(t, installMux(""), http.MethodHead, "/install.ps1"); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD: status = %d, body length %d", rec.Code, rec.Body.Len())
	}
	if rec = get(t, installMux(""), http.MethodPost, "/install.ps1"); rec.Body.String() == string(deploy.InstallPowerShell) {
		t.Error("POST /install.ps1 must not serve the script")
	}
}

func TestDownloadRoute(t *testing.T) {
	root := t.TempDir()
	assets := filepath.Join(root, "assets")
	writeFile(t, filepath.Join(root, "secret"), "outside")
	writeFile(t, filepath.Join(assets, "checksums.txt"), "abc  hearth_1.0.0_linux_amd64.tar.gz\n")
	writeFile(t, filepath.Join(assets, "hearth_1.0.0_linux_amd64.tar.gz"), "archive")
	writeFile(t, filepath.Join(assets, ".hidden"), "hidden")
	writeFile(t, filepath.Join(assets, "sub", "file"), "nested")
	if err := os.Symlink(filepath.Join(root, "secret"), filepath.Join(assets, "escape")); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, assetsDir, path string
		wantStatus            int
		wantBody              string
	}{
		{"checksums", assets, "/download/checksums.txt", http.StatusOK, "abc  hearth_1.0.0_linux_amd64.tar.gz\n"},
		{"archive", assets, "/download/hearth_1.0.0_linux_amd64.tar.gz", http.StatusOK, "archive"},
		{"no assets dir", "", "/download/checksums.txt", http.StatusNotFound, ""},
		{"missing file", assets, "/download/nope.tar.gz", http.StatusNotFound, ""},
		{"listing", assets, "/download/", http.StatusNotFound, ""},
		{"directory", assets, "/download/sub", http.StatusNotFound, ""},
		{"nested", assets, "/download/sub/file", http.StatusNotFound, ""},
		{"dotfile", assets, "/download/.hidden", http.StatusNotFound, ""},
		{"encoded traversal", assets, "/download/..%2Fsecret", http.StatusNotFound, ""},
		{"encoded dot-dot", assets, "/download/%2E%2E", http.StatusNotFound, ""},
		{"symlink out of root", assets, "/download/escape", http.StatusNotFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := get(t, installMux(tt.assetsDir), http.MethodGet, tt.path)
			body := rec.Body.String()
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.wantStatus, body)
			}
			if tt.wantBody != "" && body != tt.wantBody {
				t.Errorf("body = %q, want %q", body, tt.wantBody)
			}
			if strings.Contains(body, "outside") || strings.Contains(body, "hidden") || strings.Contains(body, "nested") {
				t.Errorf("served a file it must not: %q", body)
			}
		})
	}

	// A plain ../ path is cleaned by the mux into a redirect, never a file.
	rec := get(t, installMux(assets), http.MethodGet, "/download/../secret")
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "outside") {
		t.Errorf("/download/../secret: status %d, body %q", rec.Code, rec.Body.String())
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
