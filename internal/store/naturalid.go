// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"crypto/sha256"
	"encoding/hex"
)

// Natural-key ids (docs/design/ap-cluster.md §4.5). A table whose rows are
// unique by something other than their id derives the id from it: two hubs
// creating "the same" row make the same id, and the two writes merge into
// one row by last-writer-wins instead of colliding on the unique key. Rows
// stored before keep the ids they have.

// KubeClusterID is the id of the Kubernetes cluster named name.
func KubeClusterID(name string) string { return naturalID("kube_clusters", []byte(name)) }

// ProxmoxServerID is the id of the Proxmox server named name.
func ProxmoxServerID(name string) string { return naturalID("proxmox_servers", []byte(name)) }

// ESPHomeDeviceID is the id of the ESPHome device named name.
func ESPHomeDeviceID(name string) string { return naturalID("esphome_devices", []byte(name)) }

// OpenWrtRouterID is the id of the OpenWrt router named name.
func OpenWrtRouterID(name string) string { return naturalID("openwrt_routers", []byte(name)) }

// PanelLinkID is the id of the share link whose secret is secret: derived
// from the secret's hash, the link's unique key, and telling nothing of it.
func PanelLinkID(secret string) string {
	h := hashSecret(secret)
	return naturalID("panel_links", h[:])
}

// naturalID is the id of the row of table with unique key key: 16 hex
// digits, as the random ids before them.
func naturalID(table string, key []byte) string {
	h := sha256.New()
	h.Write([]byte("hearth natural id\x00" + table + "\x00"))
	h.Write(key)
	return hex.EncodeToString(h.Sum(nil)[:8])
}
