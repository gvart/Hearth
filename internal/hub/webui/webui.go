// SPDX-License-Identifier: AGPL-3.0-only

// Package webui serves the hub's web UI from files embedded at build time.
//
// `task build` builds web/ and copies web/dist into ./dist before compiling, so
// release binaries carry the real UI. A plain `go build` (no Node toolchain)
// still works: dist then only holds a .gitkeep and Handler serves a small
// placeholder page instead.
package webui

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var embedded embed.FS

const indexFile = "index.html"

// fallbackPage is served when the binary was built without the web UI.
const fallbackPage = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Hearth</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem">
<h1>Hearth</h1>
<p>This binary was built without the web UI. Rebuild with <code>task build</code> to embed it.</p>
</body>
</html>
`

// Handler returns an http.Handler for the embedded web UI.
func Handler() http.Handler {
	dist, err := fs.Sub(embedded, "dist")
	if err != nil {
		// fs.Sub only fails on an invalid path; "dist" is a constant.
		return fallbackHandler()
	}
	return newHandler(dist)
}

// Available reports whether the binary embeds a built web UI.
func Available() bool {
	dist, err := fs.Sub(embedded, "dist")
	if err != nil {
		return false
	}
	return hasIndex(dist)
}

func newHandler(dist fs.FS) http.Handler {
	if !hasIndex(dist) {
		return fallbackHandler()
	}
	files := http.FileServerFS(dist)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" {
			files.ServeHTTP(w, r)
			return
		}
		if _, err := fs.Stat(dist, name); errors.Is(err, fs.ErrNotExist) && path.Ext(name) == "" {
			// Client-side route (e.g. /devices/42): let the SPA handle it.
			http.ServeFileFS(w, r, dist, indexFile)
			return
		}
		files.ServeHTTP(w, r)
	})
}

func hasIndex(dist fs.FS) bool {
	_, err := fs.Stat(dist, indexFile)
	return err == nil
}

func fallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(fallbackPage))
	})
}
