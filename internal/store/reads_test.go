// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"maps"
	"slices"
	"testing"
)

// readsExempt are the commands that read rows inside their write without
// fetching the newest copy first, and why a stale copy is acceptable.
var readsExempt = map[string]string{ //nolint:gosec // op names and reasons, no credentials
	"upsert_device":          "device state is soft: last writer wins",
	"report_facts":           "device state is soft: last writer wins",
	"set_boot_time":          "device state is soft: last writer wins",
	"mark_seen":              "presence is soft: last writer wins",
	"mark_offline":           "runs on every storage member, each on the rows it holds",
	"mark_devices_offline":   "presence is soft: last writer wins",
	"set_hub_url":            "soft: each hub writes its own row",
	"record_hub_cert":        "only fills in missing values; revoked_at is set-once",
	"set_password_hash":      "runs on every storage member, each ending the sessions it holds",
	"create_session":         "reads only to prune expired sessions",
	"record_automation_run":  "reads only to prune old runs",
	"record_network_scan":    "discovery state is soft: last writer wins",
	"set_network_host_state": "discovery state is soft: last writer wins",
	"record_network_import":  "discovery state is soft: last writer wins",
	"update_panel":           "panels are soft: last writer wins",
	"delete_panel":           "panels are soft: a missed panel is refused with not found, retried",
	"remove_kube_cluster":    "a missed row is refused with not found, retried; the delete is a tombstone",
	"remove_proxmox_server":  "a missed row is refused with not found, retried; the delete is a tombstone",
	"remove_esphome_device":  "a missed row is refused with not found, retried; the delete is a tombstone",
	"remove_openwrt_router":  "a missed row is refused with not found, retried; the delete is a tombstone",
	// OPNsense firewalls (#364).
	"remove_opnsense_firewall": "a missed row is refused with not found, retried; the delete is a tombstone",
	// UniFi controllers (#365).
	"remove_unifi_controller": "a missed row is refused with not found, retried; the delete is a tombstone",
	"mark_telemetry_sent":     "telemetry state is soft",
	"revoke_ca_certs":         "runs on every storage member, each on the rows it holds",
}

// Every command that reads rows inside its write either names them in
// ReadsOf, so a sharded cluster fetches their newest copy first, or is
// exempt with a reason: a new command that reads must decide.
func TestReadsOfCoversEveryRead(t *testing.T) {
	ctx := t.Context()
	for _, cmd := range allCommands() {
		t.Run(cmd.Op(), func(t *testing.T) {
			s := openTest(t)
			read := map[string]bool{}
			s.readHook = func(table string) { read[table] = true }
			_, _ = s.ApplyLocal(ctx, cmd)
			declared := map[string]bool{}
			for _, r := range ReadsOf(cmd) {
				declared[r.Table] = true
			}
			reason, exempt := readsExempt[cmd.Op()]
			switch {
			case exempt && len(declared) > 0:
				t.Fatalf("exempt (%s) but ReadsOf names %v", reason, slices.Sorted(maps.Keys(declared)))
			case exempt:
				return
			}
			for table := range read {
				if !declared[table] {
					t.Errorf("reads %s, which ReadsOf does not name", table)
				}
			}
		})
	}
	for op := range readsExempt {
		if !slices.ContainsFunc(allCommands(), func(c Command) bool { return c.Op() == op }) {
			t.Errorf("exempt op %q is no command", op)
		}
	}
}

func TestReadKeysQuery(t *testing.T) {
	r := Read{Table: "certs", Where: `device_id = ?`, Args: Values{"pi"}}
	if got, want := r.KeysQuery(), `SELECT serial FROM certs WHERE device_id = ?`; got != want {
		t.Errorf("KeysQuery = %q, want %q", got, want)
	}
	if _, ok := r.Ref(); ok {
		t.Error("a WHERE read has a ref")
	}
	ref, ok := Read{Table: "tokens", Key: Values{[]byte{1}}}.Ref()
	if !ok || ref.Table != "tokens" || len(ref.Key) != 1 {
		t.Errorf("Ref = %+v, %v", ref, ok)
	}
}
