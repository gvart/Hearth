// SPDX-License-Identifier: AGPL-3.0-only

// Package webui serves the hub's web UI from files embedded at build time.
//
// `task build` builds web/ and copies web/dist into ./dist before compiling, so
// release binaries carry the real UI. Text assets are embedded gzipped only
// (scripts/embed-webui.mjs) and served with Content-Encoding: gzip, or
// unpacked for a client that does not accept gzip. A plain `go build` (no Node
// toolchain) still works: dist then only holds a .gitkeep and Handler serves a
// small placeholder page instead.
package webui

import (
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/binary"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

//go:embed all:dist
var embedded embed.FS

const (
	indexFile = "index.html"
	assetsDir = "assets" // Vite's build.assetsDir
	gzExt     = ".gz"    // suffix of the gzipped copies scripts/embed-webui.mjs embeds
)

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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if containsDotDot(r.URL.Path) {
			// As http.ServeFile does.
			http.Error(w, "invalid URL path", http.StatusBadRequest)
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		switch {
		case name == "":
			serveFile(w, r, dist, indexFile)
		case name == indexFile:
			// As http.FileServer does: index.html is served at its directory.
			w.Header().Set("Location", "./")
			w.WriteHeader(http.StatusMovedPermanently)
		case serveFile(w, r, dist, name):
		case name == assetsDir || strings.HasPrefix(name, assetsDir+"/"):
			// Missing bundle files and directory listings are plain 404s.
			http.NotFound(w, r)
		default:
			// Client-side route, including ones with dots such as
			// /devices/nas.lan or /devices/192.168.1.10: the SPA handles it.
			serveFile(w, r, dist, indexFile)
		}
	})
}

// serveFile serves the file name, from its gzipped copy name.gz when the
// build embedded one, and reports whether there was such a file.
func serveFile(w http.ResponseWriter, r *http.Request, dist fs.FS, name string) bool {
	if strings.HasSuffix(name, gzExt) {
		// Only the names the UI was built with are served, not the .gz copies.
		return false
	}
	if f, err := dist.Open(name + gzExt); err == nil {
		defer func() { _ = f.Close() }()
		serveGzipped(w, r, name, f)
		return true
	}
	f, err := dist.Open(name)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		return false
	}
	content, err := readSeeker(f)
	if err != nil {
		http.Error(w, "cannot read "+name, http.StatusInternalServerError)
		return true
	}
	setContentType(w, name)
	http.ServeContent(w, r, name, info.ModTime(), content)
	return true
}

// readSeeker returns f as an io.ReadSeeker, as embedded files are, or else
// reads it into memory.
func readSeeker(f fs.File) (io.ReadSeeker, error) {
	if rs, ok := f.(io.ReadSeeker); ok {
		return rs, nil
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

// serveGzipped serves gz, the gzipped content of name: as is to a client
// that accepts gzip, unpacked otherwise.
func serveGzipped(w http.ResponseWriter, r *http.Request, name string, gz fs.File) {
	setContentType(w, name)
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Add("Vary", "Accept-Encoding")
	content, err := readSeeker(gz)
	if err != nil {
		http.Error(w, "cannot read "+name, http.StatusInternalServerError)
		return
	}
	if acceptsGzip(strings.Join(r.Header.Values("Accept-Encoding"), ",")) {
		w.Header().Set("Content-Encoding", "gzip")
		if r.Header.Get("Range") == "" {
			// http.ServeContent leaves the length out of an encoded
			// response; the whole file is sent, so its size is the length.
			if size, err := content.Seek(0, io.SeekEnd); err == nil {
				w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			}
		}
		http.ServeContent(w, r, name, time.Time{}, content)
		return
	}
	// gzip's trailer ends with the unpacked size (mod 2^32, plenty here).
	var trailer [4]byte
	if _, err := content.Seek(-int64(len(trailer)), io.SeekEnd); err == nil {
		if _, err := io.ReadFull(content, trailer[:]); err == nil {
			w.Header().Set("Content-Length", strconv.FormatUint(uint64(binary.LittleEndian.Uint32(trailer[:])), 10))
		}
	}
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		w.Header().Del("Content-Length")
		http.Error(w, "cannot read "+name, http.StatusInternalServerError)
		return
	}
	zr, err := gzip.NewReader(content)
	if err != nil {
		w.Header().Del("Content-Length")
		http.Error(w, "cannot read "+name, http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	// The input is one of the build's own embedded files, never a client's.
	_, _ = io.Copy(w, zr) //nolint:gosec // G110: embedded files are no decompression bomb
}

// setContentType sets the media type from the name's extension, as
// http.FileServer does, so that a gzipped file is not sniffed as gzip.
func setContentType(w http.ResponseWriter, name string) {
	ext := path.Ext(name)
	ctype := mime.TypeByExtension(ext)
	switch {
	case ext == ".webmanifest":
		// Not in Go's built-in MIME table.
		ctype = "application/manifest+json"
	case ctype == "":
		// http.ServeContent sniffs a plain file's content then, as
		// http.FileServer did; serveGzipped falls back to octet-stream.
		return
	}
	w.Header().Set("Content-Type", ctype)
}

// acceptsGzip reports whether an Accept-Encoding value allows gzip: gzip, or
// else *, with a q above 0.
func acceptsGzip(accept string) bool {
	star := false
	for part := range strings.SplitSeq(accept, ",") {
		coding, params, _ := strings.Cut(part, ";")
		switch strings.ToLower(strings.TrimSpace(coding)) {
		case "gzip", "x-gzip":
			return qualityAboveZero(params)
		case "*":
			star = qualityAboveZero(params)
		}
	}
	return star
}

// qualityAboveZero reports whether the q parameter in params, if there is
// one, is above 0.
func qualityAboveZero(params string) bool {
	for param := range strings.SplitSeq(params, ";") {
		key, value, _ := strings.Cut(strings.TrimSpace(param), "=")
		if strings.EqualFold(strings.TrimSpace(key), "q") {
			q, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			return err == nil && q > 0
		}
	}
	return true
}

// containsDotDot reports whether a URL path has a ".." element, which
// http.ServeFile refuses too.
func containsDotDot(p string) bool {
	if !strings.Contains(p, "..") {
		return false
	}
	for elem := range strings.FieldsFuncSeq(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if elem == ".." {
			return true
		}
	}
	return false
}

func hasIndex(dist fs.FS) bool {
	for _, name := range []string{indexFile + gzExt, indexFile} {
		if _, err := fs.Stat(dist, name); err == nil {
			return true
		}
	}
	return false
}

func fallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(fallbackPage))
	})
}
