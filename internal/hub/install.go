// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/gvart/hearth/deploy"
)

// assetName is a plain file name: no separators, no leading dot.
var assetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// RegisterInstallRoutes adds the unauthenticated installer routes to mux:
// GET /install.sh serves the embedded agent installer, and GET /download/{name}
// serves release archives and checksums.txt from assetsDir for
// `install.sh --from-hub`. With no assetsDir, every /download/ path is a 404.
func RegisterInstallRoutes(mux *http.ServeMux, assetsDir string) {
	mux.HandleFunc("GET /install.sh", serveInstallScript)
	mux.HandleFunc("GET /download/{name}", downloadHandler(assetsDir))
	mux.HandleFunc("/download/", http.NotFound)
}

func serveInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "install.sh", time.Time{}, bytes.NewReader(deploy.InstallScript))
}

func downloadHandler(assetsDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if assetsDir == "" || !assetName.MatchString(name) {
			http.NotFound(w, r)
			return
		}
		// OpenInRoot also refuses symlinks that point outside assetsDir.
		f, err := os.OpenInRoot(assetsDir, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, name, info.ModTime(), f)
	}
}
