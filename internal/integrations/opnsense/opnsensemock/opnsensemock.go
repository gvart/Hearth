// SPDX-License-Identifier: AGPL-3.0-only

// Package opnsensemock is a fake OPNsense firewall: the part of its REST API
// Hearth uses, for tests. It is written from the sources of OPNsense core
// (ApiControllerBase's basic auth of an API key and secret: 401 for a bad
// key, 403 for an endpoint the key's user has no privilege for, 400 for a
// JSON request with an empty body; searchRecordsetBase's rows; the
// diagnostics system, interface and traffic controllers; the firmware
// status; the Kea and dnsmasq lease searches; Unbound's service restart) and
// of the os-isc-dhcp plugin's lease search. It has never been compared with
// a real firewall.
//
// Nothing in the hearth binary imports it.
package opnsensemock

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
)

// Default API key of the mock.
const (
	Key    = "w86XNZob/8Oq8aC5r0kbNarNtdpoQU781fyoeaOBQsBwkXUt"
	Secret = "XeD26XVrJ5ilAc/EmglCRC+0j2e57tRsjHwFepOseySWLM53pJASeTA3"
)

// Request is one API request the mock received.
type Request struct {
	Method, Path string
}

// Server is the fake firewall. It is an http.Handler serving /api.
type Server struct {
	mu       sync.Mutex
	key      string
	secret   string
	denied   map[string]bool
	missing  map[string]bool
	requests []Request
	restarts int
}

// New returns a fake firewall with a few clients, accepting key and secret.
func New(key, secret string) *Server {
	return &Server{key: key, secret: secret, denied: map[string]bool{}, missing: map[string]bool{}}
}

// Deny makes path refused with 403, as for a key whose user lacks its
// privilege.
func (s *Server) Deny(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denied[path] = true
}

// Remove makes path answer 404, as on a firewall without its plugin.
func (s *Server) Remove(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.missing[path] = true
}

// SetSecret changes the secret the firewall accepts, as when the key is
// deleted and made again.
func (s *Server) SetSecret(secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secret = secret
}

// Requests returns every request received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

// Restarts counts the Unbound restarts the firewall carried out.
func (s *Server) Restarts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.restarts
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, Request{Method: r.Method, Path: r.URL.Path})
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	data, ok := s.answer(r.URL.Path)
	if !ok || s.missing[r.URL.Path] {
		writeJSON(w, http.StatusNotFound, map[string]any{"errorMessage": "Endpoint not found"})
		return
	}
	key, secret, hasAuth := r.BasicAuth()
	if !hasAuth || key != s.key || secret != s.secret {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": 401, "message": "Authentication Failed"})
		return
	}
	if s.denied[r.URL.Path] {
		writeJSON(w, http.StatusForbidden, map[string]any{"status": 403, "message": "Forbidden"})
		return
	}
	if r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body any
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": 400, "message": "Invalid JSON syntax"})
			return
		}
	}
	if r.URL.Path == "/api/unbound/service/restart" {
		// ApiMutableServiceControllerBase restarts on POST only.
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusOK, map[string]any{"response": []any{}})
			return
		}
		s.restarts++
	}
	writeJSON(w, http.StatusOK, data)
}

// answer is the reply to an authorized request of path. mu is held.
func (s *Server) answer(path string) (any, bool) {
	rows := func(rows []map[string]any) map[string]any {
		return map[string]any{"total": len(rows), "rowCount": len(rows), "current": 1, "rows": rows, "interfaces": map[string]any{}}
	}
	switch path {
	case "/api/diagnostics/system/system_information":
		return map[string]any{
			"name":     "edge.home.arpa",
			"versions": []string{"OPNsense 25.7.4-amd64", "FreeBSD 14.3-RELEASE-p2", "OpenSSL 3.0.17"},
			"updates":  "Click to view pending updates.",
		}, true
	case "/api/diagnostics/system/system_time":
		return map[string]any{
			"uptime": "12 days, 03:04:05", "datetime": "Thu Nov 27 10:00:00 UTC 2026",
			"boottime": "Sat Nov 15 06:55:55 UTC 2026", "config": "Wed Nov 26 18:00:00 UTC 2026",
			"loadavg": "0.24, 0.31, 0.29",
		}, true
	case "/api/diagnostics/system/system_resources":
		// hw.physmem arrives as a string; used is computed, a number.
		return map[string]any{"memory": map[string]any{
			"total": "8448794624", "total_frmt": "8057", "used": 2147483648, "used_frmt": "2048",
		}}, true
	case "/api/core/firmware/status":
		return map[string]any{
			"product": map[string]any{
				"product_name": "OPNsense", "product_version": "25.7.4", "product_latest": "25.7.5",
				"product_arch": "amd64", "product_series": "25.7", "product_id": "opnsense",
			},
			"status_msg": "There are 12 updates available, total download size is 140.2MiB.",
			"status":     "update", "status_reboot": "0", "upgrade_packages": []any{},
		}, true
	case "/api/dhcpv4/leases/search_lease":
		// os-isc-dhcp: a static mapping; ends is router-local time, no zone.
		return rows([]map[string]any{
			{
				"address": "192.168.1.5", "type": "static", "mac": "00:1b:a9:00:00:03", "starts": "", "ends": "",
				"hostname": "printer", "descr": "", "if_descr": "LAN", "if": "lan", "state": "active",
				"status": "online", "man": "Brother Industries",
			},
		}), true
	case "/api/kea/leases4/search":
		return rows([]map[string]any{
			{
				"address": "10.0.20.31", "hwaddr": "b8:27:eb:00:00:06", "valid_lifetime": 4000,
				"expire": 1795000000, "hostname": "pi-iot.", "state": 0, "lease_type": "dynamic",
				"if": "igb2", "if_descr": "IOT", "if_name": "opt1", "mac_info": "Raspberry Pi Foundation",
			},
			// An expired-reclaimed lease: Kea state 2.
			{
				"address": "10.0.20.40", "hwaddr": "b8:27:eb:00:00:07", "valid_lifetime": 4000,
				"expire": 1790000000, "hostname": "old-pi.", "state": 2, "lease_type": "dynamic",
				"if": "igb2", "if_descr": "IOT", "if_name": "opt1",
			},
		}), true
	case "/api/dnsmasq/leases/search":
		return rows([]map[string]any{
			{
				"expire": 1795000100, "hwaddr": "2c:cf:67:00:00:01", "address": "192.168.1.10", "hostname": "nas",
				"client_id": "01:2c:cf:67:00:00:01", "if": "igb1", "if_descr": "LAN", "if_name": "lan",
				"is_reserved": []string{"hwaddr"}, "lease_type": "static",
			},
			{
				"expire": 1795000200, "hwaddr": "a4:5e:60:00:00:02", "address": "192.168.1.23", "hostname": "pixel-8",
				"client_id": "", "if": "igb1", "if_descr": "LAN", "if_name": "lan", "is_reserved": []string{},
				"lease_type": "dynamic",
			},
			// dnsmasq writes * for a client that sent no name.
			{
				"expire": 1795000300, "hwaddr": "de:ad:be:00:00:04", "address": "192.168.1.77", "hostname": "*",
				"client_id": "", "if": "igb1", "if_descr": "LAN", "if_name": "lan", "is_reserved": []string{},
				"lease_type": "dynamic",
			},
			// An IPv6 lease: discovery and the IPv4 column leave it out.
			{
				"expire": 1795000400, "hwaddr": "a4:5e:60:00:00:02", "address": "fd00::23", "hostname": "pixel-8",
				"client_id": "", "if": "igb1", "if_descr": "LAN", "if_name": "lan", "is_reserved": []string{},
				"lease_type": "dynamic",
			},
		}), true
	case "/api/diagnostics/interface/get_arp":
		return []map[string]any{
			// The firewall's own LAN address.
			{"mac": "00:0d:b9:00:00:10", "ip": "192.168.1.1", "intf": "igb1", "expired": false, "expires": -1,
				"permanent": true, "type": "ethernet", "manufacturer": "PC Engines GmbH", "hostname": "", "intf_description": "LAN"},
			{"mac": "2c:cf:67:00:00:01", "ip": "192.168.1.10", "intf": "igb1", "expired": false, "expires": 1100,
				"permanent": false, "type": "ethernet", "manufacturer": "Raspberry Pi (Trading) Ltd", "hostname": "nas.home.arpa",
				"intf_description": "LAN"},
			{"mac": "a4:5e:60:00:00:02", "ip": "192.168.1.23", "intf": "igb1", "expired": false, "expires": 900,
				"permanent": false, "type": "ethernet", "manufacturer": "Google, Inc.", "hostname": "", "intf_description": "LAN"},
			// A host with a static address the DHCP servers do not know.
			{"mac": "f0:99:b6:00:00:05", "ip": "192.168.1.200", "intf": "igb1", "expired": false, "expires": 1180,
				"permanent": false, "type": "ethernet", "manufacturer": "Apple, Inc.", "hostname": "",
				"intf_description": "LAN"},
			{"mac": "02:22:33:00:00:08", "ip": "192.168.1.99", "intf": "igb1", "expired": true, "expires": 0,
				"permanent": false, "type": "ethernet", "manufacturer": "", "hostname": "", "intf_description": "LAN"},
		}, true
	case "/api/diagnostics/interface/get_ndp":
		return []map[string]any{
			{"mac": "00:0d:b9:00:00:10", "ip": "fe80::20d:b9ff:fe00:10%igb1", "intf": "igb1",
				"manufacturer": "PC Engines GmbH", "intf_description": "LAN"},
			{"mac": "a4:5e:60:00:00:02", "ip": "fe80::a65e:60ff:fe00:2%igb1", "intf": "igb1",
				"manufacturer": "Google, Inc.", "intf_description": "LAN"},
			{"mac": "a4:5e:60:00:00:02", "ip": "fd00::23", "intf": "igb1",
				"manufacturer": "Google, Inc.", "intf_description": "LAN"},
		}, true
	case "/api/diagnostics/traffic/interface":
		// legacy_interface_stats: ifinfo's text lines, every value a string.
		stats := func(device, name, rx, tx string) map[string]any {
			return map[string]any{
				"device": device, "driver": strings.TrimRight(device, "0123456789"), "name": name,
				"bytes received": rx, "bytes transmitted": tx, "packets received": "9120000",
				"packets transmitted": "810000", "input errors": "2", "output errors": "0", "collisions": "0",
			}
		}
		return map[string]any{
			"interfaces": map[string]any{
				"wan":  stats("igb0", "WAN", "912000000000", "81000000000"),
				"lan":  stats("igb1", "LAN", "80000000000", "905000000000"),
				"opt1": stats("igb2", "IOT", "1200000000", "640000000"),
			},
			"time": 1795000000.25,
		}, true
	case "/api/unbound/service/restart":
		return map[string]any{"response": "OK"}, true
	}
	return nil, false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
