// SPDX-License-Identifier: AGPL-3.0-only

package webui

import (
	"bytes"
	"compress/gzip"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

func TestHandler(t *testing.T) {
	t.Parallel()

	built := fstest.MapFS{
		"index.html":           {Data: []byte("<html>app</html>")},
		"assets/app.js":        {Data: []byte("console.log('hi')")},
		"manifest.webmanifest": {Data: []byte(`{"name":"Hearth"}`)},
	}
	empty := fstest.MapFS{".gitkeep": {Data: nil}}

	tests := []struct {
		name       string
		fsys       fstest.MapFS
		path       string
		wantStatus int
		wantBody   string
		wantType   string
	}{
		{name: "manifest has its media type", fsys: built, path: "/manifest.webmanifest", wantStatus: http.StatusOK, wantBody: "Hearth", wantType: "application/manifest+json"},
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
			if ct := res.Header.Get("Content-Type"); tt.wantType != "" && ct != tt.wantType {
				t.Errorf("Content-Type = %q, want %q", ct, tt.wantType)
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

func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	return buf.Bytes()
}

// TestHandlerGzipped covers a dist as scripts/embed-webui.mjs writes it: text
// assets only as .gz, binary ones as is.
func TestHandlerGzipped(t *testing.T) {
	t.Parallel()

	const (
		index = "<html>app</html>"
		app   = "console.log('hi')"
		style = "body{margin:0}"
		mf    = `{"name":"Hearth"}`
		svg   = "<svg/>"
		gz    = "gzip, deflate, br"
		html  = "text/html; charset=utf-8"
		js    = "text/javascript; charset=utf-8"
	)
	png := []byte("\x89PNG\r\n\x1a\nrest")
	dist := fstest.MapFS{
		"index.html.gz":           {Data: gzipped(t, index)},
		"assets/app.js.gz":        {Data: gzipped(t, app)},
		"assets/app.css.gz":       {Data: gzipped(t, style)},
		"manifest.webmanifest.gz": {Data: gzipped(t, mf)},
		"favicon.svg.gz":          {Data: gzipped(t, svg)},
		"icon.png":                {Data: png},
	}
	guest := http.Header{"Referrer-Policy": {"no-referrer"}, "Cache-Control": {"no-store"}}

	tests := []struct {
		name     string
		method   string
		path     string
		accept   string
		header   http.Header // set on the response before the handler runs, as guestPage does
		status   int
		body     string // unpacked body
		ctype    string
		encoding string // Content-Encoding
		vary     bool
	}{
		{name: "index gzipped", path: "/", accept: gz, status: 200, body: index, ctype: html, encoding: "gzip", vary: true},
		{name: "index plain", path: "/", status: 200, body: index, ctype: html, vary: true},
		{name: "js gzipped", path: "/assets/app.js", accept: gz, status: 200, body: app, ctype: js, encoding: "gzip", vary: true},
		{name: "js plain", path: "/assets/app.js", status: 200, body: app, ctype: js, vary: true},
		{name: "css gzipped", path: "/assets/app.css", accept: "gzip", status: 200, body: style, ctype: "text/css; charset=utf-8", encoding: "gzip", vary: true},
		{name: "svg gzipped", path: "/favicon.svg", accept: gz, status: 200, body: svg, ctype: "image/svg+xml", encoding: "gzip", vary: true},
		{name: "manifest gzipped", path: "/manifest.webmanifest", accept: gz, status: 200, body: mf, ctype: "application/manifest+json", encoding: "gzip", vary: true},
		{name: "manifest plain", path: "/manifest.webmanifest", status: 200, body: mf, ctype: "application/manifest+json", vary: true},
		{name: "png never encoded", path: "/icon.png", accept: gz, status: 200, body: string(png), ctype: "image/png"},
		{name: "gzip refused with q=0", path: "/assets/app.js", accept: "gzip;q=0, br", status: 200, body: app, ctype: js, vary: true},
		{name: "gzip refused with spaced q=0.0", path: "/assets/app.js", accept: "br, gzip ; q=0.0", status: 200, body: app, ctype: js, vary: true},
		{name: "identity only", path: "/assets/app.js", accept: "identity", status: 200, body: app, ctype: js, vary: true},
		{name: "star accepts gzip", path: "/assets/app.js", accept: "*", status: 200, body: app, ctype: js, encoding: "gzip", vary: true},
		{name: "star with q=0 refuses", path: "/assets/app.js", accept: "*;q=0", status: 200, body: app, ctype: js, vary: true},
		{name: "explicit gzip beats star q=0", path: "/assets/app.js", accept: "*;q=0, GZIP;q=0.5", status: 200, body: app, ctype: js, encoding: "gzip", vary: true},
		{name: "head gzipped", method: http.MethodHead, path: "/assets/app.js", accept: gz, status: 200, ctype: js, encoding: "gzip", vary: true},
		{name: "head plain", method: http.MethodHead, path: "/assets/app.js", status: 200, ctype: js, vary: true},
		{name: "client route falls back to index", path: "/devices/nas.lan", accept: gz, status: 200, body: index, ctype: html, encoding: "gzip", vary: true},
		{name: "client route plain", path: "/devices/42", status: 200, body: index, ctype: html, vary: true},
		{name: "missing asset is 404", path: "/assets/missing.js", accept: gz, status: 404},
		{name: "gz copy is not a URL", path: "/assets/app.js.gz", accept: gz, status: 404},
		{name: "assets dir is 404", path: "/assets/", accept: gz, status: 404},
		{name: "index.html redirects to its directory", path: "/index.html", accept: gz, status: 301},
		{name: "traversal rejected", path: "/../../etc/passwd", accept: gz, status: 400},
		{name: "guest page keeps its headers", path: "/p/TOKEN", accept: gz, header: guest, status: 200, body: index, ctype: html, encoding: "gzip", vary: true},
		{name: "guest page keeps its headers unpacked", path: "/p/TOKEN", header: guest, status: 200, body: index, ctype: html, vary: true},
	}
	handler := newHandler(dist)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			method := tt.method
			if method == "" {
				method = http.MethodGet
			}
			req := httptest.NewRequest(method, tt.path, nil)
			if tt.accept != "" {
				req.Header.Set("Accept-Encoding", tt.accept)
			}
			rec := httptest.NewRecorder()
			maps.Copy(rec.Header(), tt.header)
			handler.ServeHTTP(rec, req)

			res := rec.Result()
			if res.StatusCode != tt.status {
				t.Fatalf("status = %d, want %d", res.StatusCode, tt.status)
			}
			for k := range tt.header {
				if got, want := res.Header.Get(k), tt.header.Get(k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
			if tt.status != http.StatusOK {
				if ce := res.Header.Get("Content-Encoding"); ce != "" {
					t.Errorf("Content-Encoding = %q on a %d", ce, tt.status)
				}
				return
			}
			if ct := res.Header.Get("Content-Type"); ct != tt.ctype {
				t.Errorf("Content-Type = %q, want %q", ct, tt.ctype)
			}
			if ce := res.Header.Get("Content-Encoding"); ce != tt.encoding {
				t.Errorf("Content-Encoding = %q, want %q", ce, tt.encoding)
			}
			if vary := res.Header.Get("Vary") == "Accept-Encoding"; vary != tt.vary {
				t.Errorf("Vary = %q, want Accept-Encoding: %v", res.Header.Get("Vary"), tt.vary)
			}
			raw, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			want, body := tt.body, raw
			if method == http.MethodHead {
				want = ""
			} else if tt.encoding == "gzip" {
				zr, err := gzip.NewReader(bytes.NewReader(raw))
				if err != nil {
					t.Fatalf("body is not gzip: %v", err)
				}
				if body, err = io.ReadAll(zr); err != nil {
					t.Fatalf("gunzip body: %v", err)
				}
			}
			if string(body) != want {
				t.Errorf("body = %q, want %q", body, want)
			}
			if cl := res.Header.Get("Content-Length"); method == http.MethodGet && cl != strconv.Itoa(len(raw)) {
				t.Errorf("Content-Length = %q, want %d", cl, len(raw))
			}
		})
	}
}

func TestAcceptsGzip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		accept string
		want   bool
	}{
		{"", false},
		{"gzip", true},
		{"x-gzip", true},
		{"deflate, gzip;q=1.0, *;q=0.5", true},
		{"br", false},
		{"identity", false},
		{"gzip;q=0", false},
		{"gzip; q=0.001", true},
		{"gzip;q=abc", false},
		{"*", true},
		{"*;q=0", false},
		{"gzip;q=0, *", false},
		{"br;q=1, *;q=0.1", true},
	}
	for _, tt := range tests {
		if got := acceptsGzip(tt.accept); got != tt.want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", tt.accept, got, tt.want)
		}
	}
}
