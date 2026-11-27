// SPDX-License-Identifier: AGPL-3.0-only

// Package openwrtmock is a fake OpenWrt router: the part of uhttpd's /ubus
// JSON-RPC Hearth uses, for tests. It is written from the sources of uhttpd
// (ubus.c), rpcd (session.c, iwinfo.c, rc.c), procd (system.c) and LuCI's
// rpcd-mod-luci (luci.c), and netifd's network.device status fields as
// LuCI reads them: the null-session login, the legacy [status, data] result
// form, JSON-RPC error -32002 for a session that is unknown, expired or whose
// ACL lacks the call, -32000 for an object that is not there, and the reply
// fields of system board and info, network.device status, luci-rpc
// getDHCPLeases, iwinfo devices and assoclist, and rc init. It has never been
// compared with a real router.
//
// Nothing in the hearth binary imports it.
package openwrtmock

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"sync"
)

// Default login of the mock.
const (
	Username = "hearth"
	Password = "correct horse battery staple"
)

// Call is one ubus call the mock received.
type Call struct {
	Object, Method string
	// Args is the call's argument object.
	Args map[string]any
	// Session is the session ID the call carried.
	Session string
}

// Server is the fake router. It is an http.Handler serving /ubus.
type Server struct {
	mu       sync.Mutex
	user     string
	pass     string
	sessions map[string]bool
	denied   map[string]bool
	missing  map[string]bool
	calls    []Call
	logins   int
	restarts int
	leases   []map[string]any
	assoc    map[string][]map[string]any
}

// New returns a fake router with a few clients, accepting user and password.
func New(user, password string) *Server {
	return &Server{
		user: user, pass: password, sessions: map[string]bool{}, denied: map[string]bool{}, missing: map[string]bool{},
		leases: []map[string]any{
			{"expires": 43000, "hostname": "nas", "macaddr": "2c:cf:67:00:00:01", "ipaddr": "192.168.1.10"},
			{"expires": 39000, "hostname": "pixel-8", "macaddr": "a4:5e:60:00:00:02", "ipaddr": "192.168.1.23"},
			// A static lease: rpcd-mod-luci sends expires as a u8 0, false in JSON.
			{"expires": false, "hostname": "printer", "macaddr": "00:1b:a9:00:00:03", "ipaddr": "192.168.1.5"},
			{"expires": 12000, "hostname": "*", "macaddr": "de:ad:be:00:00:04", "ipaddr": "192.168.1.77"},
		},
		assoc: map[string][]map[string]any{
			"phy0-ap0": {
				// libubus sends the signal as a u32 holding a negative int32.
				{"mac": "A4:5E:60:00:00:02", "signal": uint32(4294967234), "noise": -95, "inactive": 1200, "connected_time": 3600},
			},
			"phy1-ap0": {
				{"mac": "F0:99:B6:00:00:05", "signal": -71, "noise": -92, "inactive": 30000, "connected_time": 120},
			},
		},
	}
}

// Expire forgets every session, as rpcd does once a session timed out.
func (s *Server) Expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.sessions)
}

// Deny makes object.method refused for every session, as a login whose ACL
// lacks it is.
func (s *Server) Deny(object, method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denied[object+"."+method] = true
}

// Remove makes object absent, as on a router without its package.
func (s *Server) Remove(object string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.missing[object] = true
}

// SetPassword changes the password the router accepts.
func (s *Server) SetPassword(p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pass = p
}

// Calls returns every call received so far, logins included.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// Logins counts the successful logins.
func (s *Server) Logins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// Restarts counts the dnsmasq restarts the router carried out.
func (s *Server) Restarts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.restarts
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ubus" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID     any               `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeRPCError(w, nil, -32700, "Parse error")
		return
	}
	var sid, object, method string
	args := map[string]any{}
	if req.Method != "call" || len(req.Params) != 4 ||
		json.Unmarshal(req.Params[0], &sid) != nil || json.Unmarshal(req.Params[1], &object) != nil ||
		json.Unmarshal(req.Params[2], &method) != nil || json.Unmarshal(req.Params[3], &args) != nil {
		writeRPCError(w, req.ID, -32600, "Invalid request")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, Call{Object: object, Method: method, Args: args, Session: sid})
	if s.missing[object] {
		writeRPCError(w, req.ID, -32000, "Object not found")
		return
	}
	if object == "session" && method == "login" {
		if args["username"] != s.user || args["password"] != s.pass {
			writeResult(w, req.ID, 6, nil)
			return
		}
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		id := hex.EncodeToString(b)
		s.sessions[id] = true
		s.logins++
		writeResult(w, req.ID, 0, map[string]any{
			"ubus_rpc_session": id, "timeout": 300, "expires": 299,
			"acls": map[string]any{}, "data": map[string]any{"username": s.user},
		})
		return
	}
	if !s.sessions[sid] || s.denied[object+"."+method] {
		writeRPCError(w, req.ID, -32002, "Access denied")
		return
	}
	data, status := s.answer(object, method, args)
	writeResult(w, req.ID, status, data)
}

// answer is the reply to an authorized call. mu is held.
func (s *Server) answer(object, method string, args map[string]any) (any, int) {
	switch object + "." + method {
	case "system.board":
		return map[string]any{
			"kernel": "6.6.73", "hostname": "gateway", "system": "ARMv8 Processor rev 4",
			"model": "GL.iNet GL-MT6000", "board_name": "glinet,gl-mt6000", "rootfs_type": "squashfs",
			"release": map[string]any{
				"distribution": "OpenWrt", "version": "24.10.0", "revision": "r28427-6df0e3d02a",
				"target": "mediatek/filogic", "description": "OpenWrt 24.10.0 r28427-6df0e3d02a",
			},
		}, 0
	case "system.info":
		return map[string]any{
			"localtime": 1764200000, "uptime": 864000, "load": []int{19660, 13107, 6553},
			"memory": map[string]any{
				"total": 1031000064, "free": 700000000, "shared": 1000000, "buffered": 0,
				"available": 780000000, "cached": 90000000,
			},
		}, 0
	case "network.device.status":
		dev := func(kind string, up bool, mac string, rx, tx int64) map[string]any {
			return map[string]any{
				"type": kind, "up": up, "carrier": up, "macaddr": mac,
				"statistics": map[string]any{
					"rx_bytes": rx, "tx_bytes": tx, "rx_packets": rx / 1000, "tx_packets": tx / 1000,
					"rx_errors": 0, "tx_errors": 0,
				},
			}
		}
		return map[string]any{
			"lo":       dev("Network device", true, "00:00:00:00:00:00", 5000, 5000),
			"eth1":     dev("Network device", true, "94:83:c4:00:00:10", 912000000000, 81000000000),
			"br-lan":   dev("bridge", true, "94:83:c4:00:00:11", 80000000000, 905000000000),
			"lan2":     dev("Network device", false, "94:83:c4:00:00:12", 0, 0),
			"phy0-ap0": dev("Network device", true, "94:83:c4:00:00:13", 12000000000, 64000000000),
		}, 0
	case "luci-rpc.getDHCPLeases":
		return map[string]any{"dhcp_leases": s.leases, "dhcp6_leases": []any{}}, 0
	case "iwinfo.devices":
		return map[string]any{"devices": []string{"phy0-ap0", "phy1-ap0"}}, 0
	case "iwinfo.assoclist":
		dev, _ := args["device"].(string)
		list, ok := s.assoc[dev]
		if !ok {
			return nil, 4
		}
		return map[string]any{"results": list}, 0
	case "rc.init":
		if args["name"] != "dnsmasq" || args["action"] != "restart" {
			return nil, 2
		}
		s.restarts++
		return nil, 0
	}
	return nil, 3 // UBUS_STATUS_METHOD_NOT_FOUND
}

func writeResult(w http.ResponseWriter, id any, status int, data any) {
	result := []any{status}
	if data != nil {
		result = append(result, data)
	}
	writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeRPCError(w http.ResponseWriter, id any, code int, msg string) {
	writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
