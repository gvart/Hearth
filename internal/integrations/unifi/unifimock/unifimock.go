// SPDX-License-Identifier: AGPL-3.0-only

// Package unifimock is a fake UniFi Network controller: the part of its API
// Hearth uses, for tests. It serves either a UniFi OS console or a classic
// self-hosted controller, written from the behaviour of maintained clients
// of the API (Art-of-WiFi's UniFi-API-client, unifi-cli) and the fields of
// their documented responses:
//
//   - the classic login, POST /api/login, which sets the unifises cookie
//     and refuses a bad password with 400 api.err.Invalid;
//   - the UniFi OS login, POST /api/auth/login, which sets the TOKEN cookie,
//     sends X-CSRF-Token, refuses a bad password with 401, and wants that
//     token back on every POST;
//   - on UniFi OS, an API key (X-API-KEY) in place of a login, and the
//     Network application under /proxy/network;
//   - the {"meta": {"rc": ...}, "data": [...]} envelope, 401
//     api.err.LoginRequired for an unknown or expired session, 403
//     api.err.NoPermission for an endpoint the account may not use, and 400
//     api.err.NoSiteContext for an unknown site;
//   - stat/device, stat/sta, stat/health and cmd/devmgr's restart.
//
// It has never been compared with a real controller.
//
// Nothing in the hearth binary imports it.
package unifimock

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
)

// Default credentials of the mock.
const (
	Username = "hearth"
	Password = "correct horse battery staple"
	APIKey   = "unifi-api-key-0123456789abcdef" //nolint:gosec // a test credential
	Site     = "default"
)

// Controller kinds.
const (
	UniFiOS = "unifi_os"
	Classic = "classic"
)

// Request is one request the mock received.
type Request struct {
	Method, Path string
	// APIKey, Session and CSRF are what the request carried.
	APIKey, Session, CSRF string
	// Body is a POST's JSON body.
	Body map[string]any
}

// Server is the fake controller. It is an http.Handler.
type Server struct {
	kind string

	mu       sync.Mutex
	user     string
	pass     string
	key      string
	sessions map[string]string // session cookie value -> its CSRF token
	issued   []string
	denied   map[string]bool
	requests []Request
	logins   int
	restarts []string
}

// New returns a fake controller of kind (UniFiOS or Classic) with a few
// devices and clients, accepting Username and Password, and APIKey on UniFi OS.
func New(kind string) *Server {
	return &Server{kind: kind, user: Username, pass: Password, key: APIKey, sessions: map[string]string{}, denied: map[string]bool{}}
}

func (s *Server) cookieName() string {
	if s.kind == UniFiOS {
		return "TOKEN"
	}
	return "unifises"
}

// Expire forgets every session, as the controller does once one timed out.
func (s *Server) Expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.sessions)
}

// Deny makes endpoint (such as "stat/health") refused with 403, as for an
// admin whose role lacks it.
func (s *Server) Deny(endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denied[endpoint] = true
}

// SetPassword changes the password the controller accepts.
func (s *Server) SetPassword(p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pass = p
}

// SetAPIKey changes the API key the controller accepts.
func (s *Server) SetAPIKey(k string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key = k
}

// Requests returns every request received so far, logins included.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

// Logins counts the successful logins.
func (s *Server) Logins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// Restarts lists the MACs of the devices the controller restarted.
func (s *Server) Restarts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.restarts)
}

// Secrets returns every session cookie value and CSRF token the mock
// issued, for tests that check none leaks.
func (s *Server) Secrets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.issued)
}

func token() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req := Request{Method: r.Method, Path: r.URL.Path, APIKey: r.Header.Get("X-API-KEY"), CSRF: r.Header.Get("X-CSRF-Token")}
	if c, err := r.Cookie(s.cookieName()); err == nil {
		req.Session = c.Value
	}
	if r.Method == http.MethodPost {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req.Body)
	}
	s.requests = append(s.requests, req)

	loginPath, prefix := "/api/login", ""
	if s.kind == UniFiOS {
		loginPath, prefix = "/api/auth/login", "/proxy/network"
	}
	if r.URL.Path == loginPath && r.Method == http.MethodPost {
		s.login(w, req)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, prefix+"/api/s/")
	site, endpoint, ok2 := strings.Cut(rest, "/")
	if !ok || !ok2 {
		http.NotFound(w, r)
		return
	}
	switch {
	case s.kind == UniFiOS && req.APIKey != "":
		if req.APIKey != s.key {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{"code": 401, "message": "Unauthorized"}})
			return
		}
	default:
		csrf, ok := s.sessions[req.Session]
		if !ok || req.Session == "" {
			writeMeta(w, http.StatusUnauthorized, "api.err.LoginRequired", nil)
			return
		}
		if s.kind == UniFiOS && r.Method != http.MethodGet && req.CSRF != csrf {
			writeJSON(w, http.StatusForbidden, map[string]any{"message": "Invalid CSRF Token"})
			return
		}
	}
	if site != Site {
		writeMeta(w, http.StatusBadRequest, "api.err.NoSiteContext", nil)
		return
	}
	if s.denied[endpoint] {
		writeMeta(w, http.StatusForbidden, "api.err.NoPermission", nil)
		return
	}
	switch {
	case endpoint == "stat/device" && r.Method == http.MethodGet:
		writeMeta(w, http.StatusOK, "", devices)
	case endpoint == "stat/sta" && r.Method == http.MethodGet:
		writeMeta(w, http.StatusOK, "", clients)
	case endpoint == "stat/health" && r.Method == http.MethodGet:
		writeMeta(w, http.StatusOK, "", health)
	case endpoint == "cmd/devmgr" && r.Method == http.MethodPost:
		mac, _ := req.Body["mac"].(string)
		if req.Body["cmd"] != "restart" || !slices.ContainsFunc(devices, func(d map[string]any) bool { return d["mac"] == mac }) {
			writeMeta(w, http.StatusBadRequest, "api.err.UnknownDevice", nil)
			return
		}
		s.restarts = append(s.restarts, mac)
		writeMeta(w, http.StatusOK, "", []any{})
	default:
		writeMeta(w, http.StatusNotFound, "api.err.NotFound", nil)
	}
}

// login answers a login. mu is held.
func (s *Server) login(w http.ResponseWriter, req Request) {
	if req.Body["username"] != s.user || req.Body["password"] != s.pass {
		if s.kind == UniFiOS {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"code": "AUTHENTICATION_FAILED_INVALID_CREDENTIALS", "message": "Invalid username or password", "level": "debug",
			})
			return
		}
		writeMeta(w, http.StatusBadRequest, "api.err.Invalid", nil)
		return
	}
	session, csrf := token(), token()
	s.sessions[session] = csrf
	s.issued = append(s.issued, session, csrf)
	s.logins++
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: session, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	if s.kind == UniFiOS {
		w.Header().Set("X-CSRF-Token", csrf)
		writeJSON(w, http.StatusOK, map[string]any{"unique_id": "u-1", "username": s.user, "isOwner": false})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: csrf, Path: "/", Secure: true}) //nolint:gosec // as a classic controller sets it
	writeMeta(w, http.StatusOK, "", []any{})
}

// The site: a gateway, a switch and two access points, and their clients.
var (
	devices = []map[string]any{
		{
			"_id": "d1", "mac": "74:ac:b9:00:00:01", "ip": "203.0.113.7", "name": "Dream Machine", "model": "UDMPRO", "type": "udm",
			"version": "4.0.21.9965", "state": 1, "adopted": true, "uptime": 1728000, "num_sta": 6,
		},
		{
			"_id": "d2", "mac": "74:ac:b9:00:00:02", "ip": "192.168.1.2", "name": "Rack switch", "model": "USL8LP", "type": "usw",
			"version": "7.1.26.15869", "state": 1, "adopted": true, "uptime": 1727000, "num_sta": 2,
		},
		{
			"_id": "d3", "mac": "74:ac:b9:00:00:03", "ip": "192.168.1.3", "name": "Living room AP", "model": "UAL6", "type": "uap",
			"version": "6.6.77.15402", "state": 1, "adopted": true, "uptime": 860000, "num_sta": 2,
		},
		{
			"_id": "d4", "mac": "74:ac:b9:00:00:04", "ip": "192.168.1.4", "name": "Office AP", "model": "UALR6v2", "type": "uap",
			"version": "6.6.77.15402", "state": 0, "adopted": true, "uptime": 0, "num_sta": 0,
		},
	}
	clients = []map[string]any{
		{
			"mac": "2c:cf:67:00:00:10", "ip": "192.168.1.10", "hostname": "nas", "oui": "Synology", "is_wired": true,
			"sw_mac": "74:ac:b9:00:00:02", "sw_port": 3, "last_seen": 1764200000, "network": "Default",
		},
		{
			"mac": "a4:5e:60:00:00:11", "ip": "192.168.1.23", "hostname": "Pixel-8", "name": "Ana's phone", "oui": "Google",
			"is_wired": false, "ap_mac": "74:ac:b9:00:00:03", "essid": "home", "signal": -58, "rssi": 38, "last_seen": 1764200010,
		},
		{
			"mac": "f0:99:b6:00:00:12", "ip": "192.168.1.31", "hostname": "laptop", "oui": "Apple", "is_wired": false,
			"ap_mac": "74:ac:b9:00:00:03", "essid": "home", "signal": -67, "last_seen": 1764200005,
		},
		{
			"mac": "00:1b:a9:00:00:13", "ip": "192.168.1.5", "oui": "Brother", "is_wired": true,
			"sw_mac": "74:ac:b9:00:00:02", "sw_port": 7, "last_seen": 1764199990,
		},
		// Associated, no address yet.
		{
			"mac": "de:ad:be:00:00:14", "hostname": "esp-plug", "is_wired": false, "ap_mac": "74:ac:b9:00:00:03",
			"essid": "iot", "signal": -80, "last_seen": 1764200011,
		},
	}
	health = []map[string]any{
		{"subsystem": "wlan", "status": "ok", "num_user": 3, "num_ap": 2, "num_adopted": 2, "num_disconnected": 1},
		{
			"subsystem": "wan", "status": "ok", "wan_ip": "203.0.113.7", "isp_name": "Example Fiber", "num_gw": 1,
			"gw_mac": "74:ac:b9:00:00:01", "tx_bytes-r": 120000, "rx_bytes-r": 2400000,
		},
		{"subsystem": "www", "status": "ok", "latency": 12, "uptime": 1728000, "xput_up": 94.2, "xput_down": 512.4},
		{"subsystem": "lan", "status": "ok", "num_user": 2, "num_sw": 1},
		{"subsystem": "vpn", "status": "unknown"},
	}
)

func writeMeta(w http.ResponseWriter, status int, msg string, data any) {
	rc := "ok"
	if msg != "" {
		rc = "error"
	}
	if data == nil {
		data = []any{}
	}
	writeJSON(w, status, map[string]any{"meta": map[string]any{"rc": rc, "msg": msg}, "data": data})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
