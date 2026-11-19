// SPDX-License-Identifier: AGPL-3.0-only

// Package beszelmock is a mock of the part of the Beszel hub API Hearth
// uses, for tests. Beszel's API is PocketBase's, and the mock is written from
// the official documentation (https://beszel.dev/guide/rest-api,
// https://pocketbase.io/docs/api-records/) and Beszel's collection schema
// (internal/migrations, internal/entities/system/system.go):
//
//   - POST /api/collections/users/auth-with-password {"identity", "password"}
//     answers {"token", "record"}, or 400 with a {"status", "message",
//     "data"} error body (the message here is the mock's own wording);
//   - GET /api/collections/systems/records?page=&perPage= with the token as
//     the Authorization header answers {"page", "perPage", "totalItems",
//     "totalPages", "items"}; a missing or wrong token sees no systems: a
//     request that does not satisfy a list rule gets "200 empty items"
//     (https://pocketbase.io/docs/api-rules-and-filters/).
//
// It has never been compared with a real server.
//
// Nothing in the hearth binary imports it.
package beszelmock

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
)

// Credentials the mock accepts by default.
const (
	Email    = "hearth@example.com"
	Password = "correct horse battery staple"
)

// token is the auth token the mock hands out.
const token = "eyJhbGciOiJIUzI1NiJ9.mock.token" //nolint:gosec // a made-up token for the mock

// Systems is the default system list, in the API's wire format.
func Systems() []map[string]any {
	sys := func(id, name, host, status string, cpu, mp, dp float64, up int) map[string]any {
		return map[string]any{
			"collectionId": "2hz5ncl8tizk5nx", "collectionName": "systems",
			"id": id, "name": name, "host": host, "port": "45876", "status": status,
			"info": map[string]any{
				"u": up, "cpu": cpu, "mp": mp, "dp": dp, "v": "0.18.0", "t": 4, "bb": 1024,
				"la": []float64{0.1, 0.2, 0.3},
			},
		}
	}
	return []map[string]any{
		sys("a1b2c3d4e5f6g7h", "pi5", "192.168.20.171", "up", 7.5, 41.2, 63.0, 864000),
		sys("b1b2c3d4e5f6g7h", "nas", "nas.lan", "up", 2.1, 18.4, 88.9, 4320000),
		sys("c1b2c3d4e5f6g7h", "old-laptop", "192.168.20.44", "down", 0, 0, 0, 0),
	}
}

// Server is the mock API. It is an http.Handler.
type Server struct {
	mu      sync.Mutex
	email   string
	pass    string
	systems []map[string]any
	perPage int
	body    string
	hang    chan struct{}
	logins  int
}

// New returns a mock with Systems, accepting email and password.
func New(email, password string) *Server {
	return &Server{email: email, pass: password, systems: Systems()}
}

// SetSystems replaces the system list.
func (s *Server) SetSystems(systems []map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.systems = systems
}

// SetMaxPerPage caps the page size, to exercise paging.
func (s *Server) SetMaxPerPage(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.perPage = n
}

// SetBody makes the systems listing answer 200 with body as is, e.g. to
// send a malformed response.
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

// Logins returns how many logins succeeded.
func (s *Server) Logins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	hang := s.hang
	s.mu.Unlock()
	if hang != nil {
		select {
		case <-hang:
		case <-r.Context().Done():
			return
		}
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/collections/users/auth-with-password":
		s.login(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/collections/systems/records":
		s.list(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"status": 404, "message": "The requested resource wasn't found.", "data": map[string]any{}})
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Identity string `json:"identity"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": 400, "message": "Failed to load the submitted data.", "data": map[string]any{}})
		return
	}
	s.mu.Lock()
	ok := in.Identity == s.email && in.Password == s.pass
	if ok {
		s.logins++
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": 400, "message": "Failed to authenticate.", "data": map[string]any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":  token,
		"record": map[string]any{"id": "u1", "collectionName": "users", "email": in.Identity, "role": "readonly"},
	})
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	systems, body, maxPer := s.systems, s.body, s.perPage
	s.mu.Unlock()
	if r.Header.Get("Authorization") != token {
		// The list rule needs an authenticated user: PocketBase answers an
		// empty list, not an error.
		systems = nil
	} else if body != "" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	page = max(page, 1)
	per, _ := strconv.Atoi(r.URL.Query().Get("perPage"))
	if per <= 0 {
		per = 30
	}
	if maxPer > 0 {
		per = min(per, maxPer)
	}
	total := len(systems)
	pages := (total + per - 1) / per
	from := min((page-1)*per, total)
	to := min(from+per, total)
	items := systems[from:to]
	if items == nil {
		items = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"page": page, "perPage": per, "totalItems": total, "totalPages": pages, "items": items,
	})
}
