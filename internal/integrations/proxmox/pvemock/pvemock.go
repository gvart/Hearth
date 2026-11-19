// SPDX-License-Identifier: AGPL-3.0-only

// Package pvemock is a mock of the part of the Proxmox VE API Hearth uses,
// for tests. It is written from the official API documentation
// (https://pve.proxmox.com/pve-docs/api-viewer/): paths, methods, the
// PVEAPIToken header, the {"data": ...} envelope, the fields of
// GET /cluster/resources and the UPID a power action returns. It has never
// been compared with a real server.
//
// Nothing in the hearth binary imports it.
package pvemock

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Token is an API token the mock accepts by default.
const Token = "hearth@pve!hub=7f8d2a54-0c1e-4f7a-9a3e-2b6d1c0e9f11" //nolint:gosec // a made-up token for the mock

// Request is one request the mock received.
type Request struct {
	Method string
	Path   string
	// Authorized says the request carried the right token.
	Authorized bool
}

// Server is the mock API. It is an http.Handler; serve it over TLS.
type Server struct {
	mu        sync.Mutex
	token     string
	resources []map[string]any
	requests  []Request
	failCode  int
	failMsg   string
}

// New returns a mock with a small cluster, accepting token.
func New(token string) *Server { return &Server{token: token, resources: fixture()} }

// fixture is the cluster, in the API's wire format: its "boolean" fields are
// 0 or 1.
func fixture() []map[string]any {
	const gib = 1 << 30
	node := func(name, status string, up int) map[string]any {
		return map[string]any{
			"id": "node/" + name, "type": "node", "node": name, "status": status, "level": "",
			"cpu": 0.12, "maxcpu": 8, "mem": 9 * gib, "maxmem": 32 * gib,
			"disk": 40 * gib, "maxdisk": 100 * gib, "uptime": up,
		}
	}
	guest := func(kind string, vmid int, name, nodeName, status string, template int) map[string]any {
		up := 0
		if status == "running" {
			up = 86400
		}
		return map[string]any{
			"id": kind + "/" + strconv.Itoa(vmid), "type": kind, "vmid": vmid, "name": name, "node": nodeName,
			"status": status, "template": template, "cpu": 0.03, "maxcpu": 2, "mem": gib, "maxmem": 4 * gib,
			"disk": 3 * gib, "maxdisk": 32 * gib, "uptime": up, "netin": 1024, "netout": 2048,
			"diskread": 4096, "diskwrite": 8192,
		}
	}
	storage := func(name, nodeName, plugin, status string, shared int) map[string]any {
		return map[string]any{
			"id": "storage/" + nodeName + "/" + name, "type": "storage", "storage": name, "node": nodeName,
			"plugintype": plugin, "status": status, "content": "images,rootdir", "shared": shared,
			"disk": 120 * gib, "maxdisk": 500 * gib,
		}
	}
	return []map[string]any{
		node("pve1", "online", 604800),
		node("pve2", "online", 259200),
		node("pve3", "offline", 0),
		guest("qemu", 100, "home-assistant", "pve1", "running", 0),
		guest("qemu", 101, "backup-vm", "pve1", "stopped", 0),
		guest("qemu", 102, "k3s-worker", "pve2", "running", 0),
		guest("qemu", 9000, "debian-12-template", "pve1", "stopped", 1),
		guest("lxc", 200, "pihole", "pve1", "running", 0),
		guest("lxc", 201, "nginx", "pve2", "stopped", 0),
		guest("lxc", 202, "gitea", "pve3", "unknown", 0),
		storage("local", "pve1", "dir", "available", 0),
		storage("local-lvm", "pve1", "lvmthin", "available", 0),
		storage("nas", "pve1", "nfs", "available", 1),
		storage("nas", "pve2", "nfs", "available", 1),
		storage("nas", "pve3", "nfs", "unknown", 1),
		// Kinds Hearth does not show.
		{"id": "pool/lab", "type": "pool", "pool": "lab"},
		{"id": "sdn/pve1/localnetwork", "type": "sdn", "sdn": "localnetwork", "node": "pve1", "status": "ok"},
	}
}

// FailWith makes every authorized request fail with code, until called with 0.
func (s *Server) FailWith(code int, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failCode, s.failMsg = code, message
}

// Requests returns every request received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

// Posts returns the paths of the POST requests received so far: the actions
// that reached the API.
func (s *Server) Posts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.requests {
		if r.Method == http.MethodPost {
			out = append(out, r.Path)
		}
	}
	return out
}

// GuestStatus returns the status of guest vmid, "" if there is none.
func (s *Server) GuestStatus(vmid int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g := s.guest(vmid); g != nil {
		status, _ := g["status"].(string)
		return status
	}
	return ""
}

// RemoveGuest deletes guest vmid, as if it was destroyed.
func (s *Server) RemoveGuest(vmid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resources = slices.DeleteFunc(s.resources, func(e map[string]any) bool { return e["vmid"] == vmid })
}

// ReplaceGuest makes vmid name another guest, as destroying a guest and
// creating one with the same VMID does. With the same kind and name it is a
// migration to node.
func (s *Server) ReplaceGuest(vmid int, kind, name, node string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g := s.guest(vmid); g != nil {
		g["id"], g["type"], g["name"], g["node"] = kind+"/"+strconv.Itoa(vmid), kind, name, node
	}
}

// guest finds guest vmid. mu is held.
func (s *Server) guest(vmid int) map[string]any {
	for _, e := range s.resources {
		if e["vmid"] == vmid {
			return e
		}
	}
	return nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	authorized := r.Header.Get("Authorization") == "PVEAPIToken="+s.token
	s.requests = append(s.requests, Request{Method: r.Method, Path: r.URL.Path, Authorized: authorized})
	if !authorized {
		reply(w, http.StatusUnauthorized, "authentication failure", nil)
		return
	}
	if s.failCode != 0 {
		reply(w, s.failCode, s.failMsg, nil)
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, "/api2/json/")
	if !ok {
		reply(w, http.StatusNotImplemented, "not implemented", nil)
		return
	}
	switch {
	case r.Method == http.MethodGet && path == "version":
		reply(w, http.StatusOK, "", map[string]any{"version": "9.0.3", "release": "9.0", "repoid": "025864202ebb6109"})
	case r.Method == http.MethodGet && path == "cluster/resources":
		reply(w, http.StatusOK, "", s.resources)
	case r.Method == http.MethodPost && strings.HasPrefix(path, "nodes/"):
		s.power(w, strings.Split(path, "/"))
	default:
		reply(w, http.StatusNotImplemented, fmt.Sprintf("Method '%s /%s' not implemented", r.Method, path), nil)
	}
}

// power serves POST nodes/{node}/{qemu|lxc}/{vmid}/status/{start|stop|reboot}.
// mu is held.
func (s *Server) power(w http.ResponseWriter, parts []string) {
	if len(parts) != 6 || (parts[2] != "qemu" && parts[2] != "lxc") || parts[4] != "status" {
		reply(w, http.StatusNotImplemented, "not implemented", nil)
		return
	}
	node, kind, verb := parts[1], parts[2], parts[5]
	vmid, err := strconv.Atoi(parts[3])
	if err != nil {
		reply(w, http.StatusBadRequest, "Parameter verification failed.", nil)
		return
	}
	g := s.guest(vmid)
	if g == nil || g["node"] != node || g["type"] != kind {
		reply(w, http.StatusInternalServerError, fmt.Sprintf("Configuration file for %s %d on %s does not exist", kind, vmid, node), nil)
		return
	}
	switch verb {
	case "start":
		g["status"], g["uptime"] = "running", 1
	case "stop", "reboot":
		if g["status"] != "running" {
			reply(w, http.StatusInternalServerError, fmt.Sprintf("%s %d not running", kind, vmid), nil)
			return
		}
		g["status"], g["uptime"] = "stopped", 0
		if verb == "reboot" {
			g["status"], g["uptime"] = "running", 1
		}
	default:
		reply(w, http.StatusNotImplemented, "not implemented", nil)
		return
	}
	reply(w, http.StatusOK, "", fmt.Sprintf("UPID:%s:0000C350:0001E240:6553F100:%s%s:%d:hearth@pve!hub:", node, kind, verb, vmid))
}

// reply writes the API's envelope. Like the real API it says what went wrong
// in the status line and in message.
func reply(w http.ResponseWriter, code int, message string, data any) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(code)
	body := map[string]any{"data": data}
	if message != "" {
		body["message"] = message + "\n"
	}
	_ = json.NewEncoder(w).Encode(body)
}
