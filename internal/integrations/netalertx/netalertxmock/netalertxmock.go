// SPDX-License-Identifier: AGPL-3.0-only

// Package netalertxmock is a mock of the part of the NetAlertX API Hearth
// uses, for tests. It is written from the official API documentation
// (https://docs.netalertx.com/API/, https://docs.netalertx.com/API_DEVICES/)
// and the API server's request schema (server/api_server/openapi/schemas.py,
// DeviceInfo): GET /devices with "Authorization: Bearer <API_TOKEN>", 403 and
// {"success": false, ...} for a wrong token, {"success": true, "devices":
// [...]} otherwise. It has never been compared with a real server.
//
// Nothing in the hearth binary imports it.
package netalertxmock

import (
	"encoding/json"
	"net/http"
	"sync"
)

// Token is an API token the mock accepts by default.
const Token = "t_9f2c41d7e0b84a6c" //nolint:gosec // a made-up token for the mock

// Devices is the default device list, in the API's wire format.
func Devices() []map[string]any {
	return []map[string]any{
		{
			"devMac": "2C:CF:67:12:34:56", "devName": "pi5", "devLastIP": "192.168.20.171",
			"devVendor": "Raspberry Pi Trading Ltd", "devStatus": "online", "devPresentLastScan": 1,
			"devIsArchived": 0, "devFavorite": 0, "devType": "Server", "devLastConnection": "2026-11-19 10:00:00",
		},
		{
			"devMac": "3c:2e:f9:00:00:03", "devName": "(unknown)", "devLastIP": "192.168.20.70",
			"devVendor": "Apple, Inc.", "devStatus": "offline", "devPresentLastScan": 0, "devIsArchived": 0,
		},
		{
			"devMac": "aa:bb:cc:00:00:09", "devName": "old-printer", "devLastIP": "192.168.20.9",
			"devVendor": "", "devStatus": "offline", "devPresentLastScan": 0, "devIsArchived": 1,
		},
		// NetAlertX's root node: not a host.
		{"devMac": "Internet", "devName": "Internet", "devLastIP": "", "devPresentLastScan": 1, "devIsArchived": 0},
	}
}

// Server is the mock API. It is an http.Handler.
type Server struct {
	mu       sync.Mutex
	token    string
	devices  []map[string]any
	body     string
	requests int
	hang     chan struct{}
}

// New returns a mock with Devices, accepting token.
func New(token string) *Server { return &Server{token: token, devices: Devices()} }

// SetBody makes GET /devices answer 200 with body as is, e.g. to send a
// malformed response.
func (s *Server) SetBody(body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = body
}

// Hang makes every request wait until release is closed or the client
// gives up.
func (s *Server) Hang(release chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hang = release
}

// Requests returns how many requests reached the handler.
func (s *Server) Requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests++
	hang, body, devices, token := s.hang, s.body, s.devices, s.token
	s.mu.Unlock()
	if hang != nil {
		select {
		case <-hang:
		case <-r.Context().Done():
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer "+token {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false, "message": "ERROR: Not authorized", "error": "Forbidden",
		})
		return
	}
	if r.Method != http.MethodGet || r.URL.Path != "/devices" {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Not Found"})
		return
	}
	if body != "" {
		_, _ = w.Write([]byte(body))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "devices": devices})
}
