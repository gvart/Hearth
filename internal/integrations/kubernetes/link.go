// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"encoding/json"
	"strings"

	"github.com/gvart/hearth/internal/store"
)

// deviceIndex finds the Hearth device a Kubernetes node runs on.
type deviceIndex struct {
	byIP   map[string][]string // address -> device IDs
	byHost map[string][]string // lowercase hostname or its first label -> device IDs
}

// deviceFacts is the part of a device's facts the link needs.
type deviceFacts struct {
	Interfaces []struct {
		IPs []string `json:"ips"`
	} `json:"interfaces"`
}

func newDeviceIndex(devices []store.Device) deviceIndex {
	idx := deviceIndex{byIP: map[string][]string{}, byHost: map[string][]string{}}
	for _, d := range devices {
		var f deviceFacts
		_ = json.Unmarshal(d.Facts, &f) // a device without facts matches by hostname only
		seen := map[string]bool{}
		for _, ifc := range f.Interfaces {
			for _, ip := range ifc.IPs {
				ip, _, _ = strings.Cut(ip, "/") // facts carry CIDR notation
				if ip != "" && !seen[ip] {
					seen[ip] = true
					idx.byIP[ip] = append(idx.byIP[ip], d.ID)
				}
			}
		}
		for _, h := range hostKeys(d.Hostname) {
			idx.byHost[h] = append(idx.byHost[h], d.ID)
		}
	}
	return idx
}

// hostKeys are the names a hostname matches by: itself and its first
// label, lowercase ("pi-1.lan" matches "pi-1" and "pi-1.lan").
func hostKeys(h string) []string {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" {
		return nil
	}
	short, _, _ := strings.Cut(h, ".")
	if short == h {
		return []string{h}
	}
	return []string{h, short}
}

// link returns the ID of the one device node runs on, or "". A node
// address matches first; failing that, the node's hostname or name. A match
// that is not unique (two devices share an address or name) links nothing.
func (idx deviceIndex) link(n Node) string {
	if id := unique(idx.byIP, n.Addresses); id != "" {
		return id
	}
	var keys []string
	for _, h := range []string{n.Hostname, n.Name} {
		keys = append(keys, hostKeys(h)...)
	}
	return unique(idx.byHost, keys)
}

// unique returns the single device ID that keys map to in m, or "" when
// none or several do.
func unique(m map[string][]string, keys []string) string {
	found := ""
	for _, k := range keys {
		for _, id := range m[k] {
			switch found {
			case "":
				found = id
			case id:
			default:
				return ""
			}
		}
	}
	return found
}
