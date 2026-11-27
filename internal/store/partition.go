// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Placement of rows and routing of commands in a sharded (AP) cluster
// (docs/design/ap-cluster.md §5.1).
//
// Every row of a sharded table has a partition key: the rows of one key live
// on the same replicas, so a command that reads and writes them runs on one
// of those replicas. The key is the device id for devices and certs, the
// panel id for panels and panel_links, the automation or runbook for their
// runs (so pruning the oldest runs of one stays on one replica), an audit
// entry's operation (so an action's entry and its outcome stay together),
// and otherwise the primary key. Small tables that every member needs, and
// tables whose commands read all their rows, are global: every storage
// member holds all of them.

// ShardBuckets is the number of digest buckets of the sharded rows, and of
// the positions on the hash ring: a row's bucket is the top 16 bits of the
// token of its partition key, and a ring position is a bucket, so every row
// of one bucket has the same replicas.
const ShardBuckets = 1 << 16

// GlobalBuckets is the number of digest buckets of the global rows.
const GlobalBuckets = 1 << 8

// partitionCols are the partition key columns of the sharded tables.
var partitionCols = map[string]string{
	"devices":          "id",
	"certs":            "device_id",
	"tokens":           "hash",
	"sessions":         "hash",
	"join_tokens":      "hash",
	"automation_runs":  "automation_id",
	"approvals":        "id",
	"approval_links":   "hash",
	"mcp_tokens":       "name",
	"runbook_runs":     "runbook_id",
	"panels":           "id",
	"panel_links":      "panel_id",
	"dashboard_tokens": "id",
	"device_routes":    "device_id",
	"device_ceilings":  "device_id",
}

// globalTables are replicated to every storage member.
var globalTables = map[string]bool{
	"admin":           true,
	"telemetry":       true,
	"cluster_hubs":    true,
	"hub_certs":       true,
	"ca_rotations":    true,
	"kube_clusters":   true,
	"proxmox_servers": true,
	"esphome_devices": true,
	"openwrt_routers": true,
	// OPNsense firewalls (#364).
	"opnsense_firewalls": true,
	// UniFi controllers (#365).
	"unifi_controllers": true,
	"network_hosts":     true,
	"config_docs":       true, // item 5 (ap-config): every member serves the configuration
}

// criticalTables are written with W = min(2, N) acknowledgements.
var criticalTables = map[string]bool{
	auditTable:         true,
	"certs":            true,
	"config_docs":      true,
	"hub_certs":        true,
	"tokens":           true,
	"join_tokens":      true,
	"mcp_tokens":       true,
	"dashboard_tokens": true,
	"approvals":        true,
	"approval_links":   true,
	"panel_links":      true,
	"runbook_runs":     true,
	"sessions":         true,
	"admin":            true,
	"ca_rotations":     true,
	"device_ceilings":  true,
}

// GlobalTable reports whether table is replicated to every storage member.
func GlobalTable(table string) bool { return globalTables[table] }

// CriticalTable reports whether writes to table wait for W = min(2, N)
// replicas.
func CriticalTable(table string) bool { return criticalTables[table] }

// ReplicatedTables are the replicated tables, the audit log included, in
// dependency order: a parent before the tables whose rows reference it, so
// a batch of rows merged in this order meets every foreign key.
func ReplicatedTables() []string {
	out := []string{"devices", "panels"}
	for _, t := range sortedTables() {
		if t != "devices" && t != "panels" {
			out = append(out, t)
		}
	}
	return append(out, auditTable)
}

// tableRank is each replicated table's place in ReplicatedTables.
var tableRank = func() map[string]int {
	m := map[string]int{}
	for i, t := range ReplicatedTables() {
		m[t] = i
	}
	return m
}()

// TableRank is table's place in ReplicatedTables: sort a batch of rows by
// it to merge parents first.
func TableRank(table string) int { return tableRank[table] }

// Placement is where a row lives: on every storage member (Global), or on
// the replicas of its partition Key.
type Placement struct {
	Global bool
	Key    string
}

// Token is the position of partition key on the hash ring.
func Token(key string) uint64 {
	h := sha256.Sum256([]byte(key))
	return binary.BigEndian.Uint64(h[:8])
}

// BucketOf is the shard bucket of token.
func BucketOf(token uint64) int { return int(token >> 48) }

// keyString renders a key column's value as a partition key.
func keyString(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case []byte:
		return hex.EncodeToString(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// PlacementOf returns where the row of table with columns r lives.
func PlacementOf(table string, r map[string]any) (Placement, error) {
	if globalTables[table] {
		return Placement{Global: true}, nil
	}
	if table == auditTable {
		return Placement{Key: auditPartition(r)}, nil
	}
	col, ok := partitionCols[table]
	if !ok {
		return Placement{}, fmt.Errorf("placement: unknown table %q", table)
	}
	k := keyString(r[col])
	if k == "" {
		return Placement{}, fmt.Errorf("placement: %s row without %s", table, col)
	}
	return Placement{Key: k}, nil
}

// Placement returns where m's row lives.
func (m Mutation) Placement() (Placement, error) { return PlacementOf(m.Table, m.Row) }

// parentKeys are the tables with a foreign key: the column, and the table
// it references. A child has its parent's partition key, so every replica
// of the child holds the parent, except a stand-in.
var parentKeys = map[string][2]string{
	"certs":       {"device_id", "devices"},
	"panel_links": {"panel_id", "panels"},
}

// ParentRef returns the row m's row references, if its table has a foreign
// key: a member that takes m must hold it first.
func (m Mutation) ParentRef() (RowRef, bool) {
	fk, ok := parentKeys[m.Table]
	if !ok {
		return RowRef{}, false
	}
	v, ok := m.Row[fk[0]]
	if !ok || v == nil {
		return RowRef{}, false
	}
	return RowRef{Table: fk[1], Key: Values{v}}, true
}

// auditPartition is the partition key of an audit entry: its operation, so
// an action's entry and its outcome stay on the same replicas and the fold
// of the two runs on one; else its once-key, so AppendAuditOnce finds the
// entry it would repeat; else the fields every replica of the entry has.
func auditPartition(r map[string]any) string {
	detail, _ := r["detail"].(string)
	if op := auditOpOf(detail); op != "" {
		return "audit-op:" + op
	}
	if k, _ := r["audit_key"].(string); k != "" {
		return "audit-key:" + k
	}
	return "audit:" + strings.Join([]string{
		keyString(r["ts"]), keyString(r["actor_kind"]), keyString(r["actor_id"]),
		keyString(r["action"]), keyString(r["target"]),
	}, "\x00")
}

// auditOpOf returns the operation id an entry's detail carries, as entry or
// as outcome; "" if none.
func auditOpOf(detail string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(detail), &m) != nil {
		return ""
	}
	for _, k := range []string{AuditOpKey, AuditOutcomeOfKey} {
		raw, ok := m[k]
		if !ok || string(raw) == "null" {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
		return string(raw)
	}
	return ""
}

// RouteKind says where a command runs in a sharded cluster.
type RouteKind int

const (
	// RouteKey runs the command on one replica of Route.Key, which copies
	// the rows it wrote to the other replicas.
	RouteKey RouteKind = iota
	// RouteGlobal runs the command on one storage member, which copies the
	// rows it wrote to every other: it writes global tables only.
	RouteGlobal
	// RouteEvery runs the command on every storage member, each on the rows
	// it holds; their results merge with MergeResults.
	RouteEvery
	// RouteSplit splits the command into one per partition key with
	// SplitCommand; their results merge with MergeResults.
	RouteSplit
)

// Route says where a command runs and how many replicas must take it.
type Route struct {
	Kind RouteKind
	// Key is the partition key of a RouteKey command.
	Key string
	// Critical commands wait for W = min(2, N) replicas.
	Critical bool
	// First commands of a RouteKey run on the first live replica of their
	// key, even on a member that is another replica: of two such commands
	// that read and write one row, one replica runs both, in turn.
	First bool
}

// ErrNoRoute refuses a command that has no place in a sharded cluster.
var ErrNoRoute = errors.New("command has no route in a sharded cluster")

// RouteOf returns where cmd runs in a sharded cluster.
func RouteOf(cmd Command) (Route, error) {
	key := func(k string, critical bool) (Route, error) {
		if k == "" {
			return Route{}, fmt.Errorf("%w: %s without a partition key", ErrNoRoute, cmd.Op())
		}
		return Route{Kind: RouteKey, Key: k, Critical: critical}, nil
	}
	global := func(critical bool) (Route, error) { return Route{Kind: RouteGlobal, Critical: critical}, nil }
	switch c := cmd.(type) {
	case UpsertDevice:
		return key(c.ID, false)
	case ReportFacts:
		return key(c.ID, false)
	case MarkSeen:
		return key(c.ID, false)
	case SetBootTime:
		return key(c.ID, false)
	case SetDeviceCeiling:
		return key(c.DeviceID, true)
	case SetDeviceRoute:
		return key(c.DeviceID, false)
	case MarkOffline:
		return Route{Kind: RouteEvery}, nil
	case MarkDevicesOffline:
		return Route{Kind: RouteSplit}, nil
	case SetHubURL:
		return global(false)
	case RecordHubCert, RevokeHubCerts, PutConfigDocs, DeleteConfigDoc:
		return global(true)
	case SetPasswordHash:
		// It ends every session, and each storage member holds only its
		// share of them: each ends the ones it holds.
		return Route{Kind: RouteEvery, Critical: true}, nil
	case StartCARotation, AdvanceCARotation:
		return global(true)
	case RevokeCACerts:
		return Route{Kind: RouteEvery}, nil
	case ResealSecrets:
		// One secret per command in a sharded cluster: a runbook run's is
		// written on its runbook's replicas, the others are global.
		if len(c.Secrets) != 1 {
			return Route{}, fmt.Errorf("%w: re-seal one secret per command in a sharded cluster", ErrNoRoute)
		}
		if sec := c.Secrets[0]; sec.Table == SealedRunbookRuns {
			return key(sec.Key, true)
		}
		return global(true)
	case CreateToken:
		return key(keyString(c.Hash), true)
	case ConsumeToken:
		return key(keyString(c.Hash), true)
	case CreateJoinToken:
		return key(keyString(c.Hash), true)
	case ConsumeJoinToken:
		return key(keyString(c.Hash), true)
	case CreateCert:
		return key(c.DeviceID, true)
	case RevokeDevice:
		return key(c.DeviceID, true)
	case PinCert:
		return key(c.DeviceID, true)
	case AppendAudit:
		return key(auditPartition(c.row("")), true)
	case AppendAuditOnce:
		return key(auditPartition(c.row(c.Key)), true)
	case CreateSession:
		return key(keyString(c.Hash), true)
	case DeleteSession:
		return key(keyString(c.Hash), true)
	case CreateDashboardToken:
		return key(c.ID, true)
	case RevokeDashboardToken:
		return key(c.ID, true)
	case CreateMCPToken:
		return key(c.Name, true)
	case RevokeMCPToken:
		return key(c.Name, true)
	case CreateApproval:
		return key(c.ID, true)
	case DecideApproval:
		return key(c.ID, true)
	case CreateApprovalLink:
		return key(keyString(c.Hash), true)
	case UseApprovalLink:
		return key(keyString(c.Hash), true)
	case CreatePanel:
		return key(c.ID, false)
	case UpdatePanel:
		return key(c.ID, false)
	case DeletePanel:
		return key(c.ID, false)
	case CreatePanelLink:
		return key(c.PanelID, true)
	case RevokePanelLink:
		return key(c.PanelID, true)
	case RecordAutomationRun:
		return key(c.AutomationID, false)
	case CreateRunbookRun:
		return key(c.RunbookID, true)
	case SaveRunbookRun:
		// Its version check runs on one replica: two saves from one
		// version, from two masters, are decided there and one is refused.
		r, err := key(c.RunbookID, true)
		r.First = true
		return r, err
	case AddKubeCluster, RemoveKubeCluster, AddProxmoxServer, RemoveProxmoxServer,
		SetTelemetry, MarkTelemetrySent, RecordNetworkScan, SetNetworkHostState, RecordNetworkImport:
		return global(false)
	case AddESPHomeDevice, RemoveESPHomeDevice:
		return global(false)
	case AddOpenWrtRouter, RemoveOpenWrtRouter:
		return global(false)
	case AddOPNsenseFirewall, RemoveOPNsenseFirewall:
		return global(false)
	case AddUniFiController, RemoveUniFiController:
		return global(false)
	}
	return Route{}, fmt.Errorf("%w: %s", ErrNoRoute, cmd.Op())
}

// row is the audit_log row c appends, with once-key key, for placement.
func (c AppendAudit) row(key string) map[string]any {
	return map[string]any{
		"ts": c.TS, "actor_kind": c.ActorKind, "actor_id": c.ActorID, "action": c.Action, "target": c.Target,
		"detail": c.Detail, "audit_key": key,
	}
}

// SplitCommand splits a RouteSplit command into one command per group:
// group maps a partition key to the group (the member) that runs it. The
// commands keep cmd's stamp.
func SplitCommand(cmd Command, group func(key string) string) (map[string]Command, error) {
	switch c := cmd.(type) {
	case MarkDevicesOffline:
		parts := map[string][]string{}
		for _, id := range c.IDs {
			g := group(id)
			parts[g] = append(parts[g], id)
		}
		out := make(map[string]Command, len(parts))
		for g, ids := range parts {
			out[g] = MarkDevicesOffline{Stamp: c.Stamp, IDs: ids, Cutoff: c.Cutoff}
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: %s does not split", ErrNoRoute, cmd.Op())
}

// MergeResults merges the results of the parts of a RouteEvery or
// RouteSplit command: devices by id (once each, in id order), counts
// summed for a split command and the largest for one every member ran (each
// replica of a row counts it).
func MergeResults(cmd Command, rs []Result) Result {
	var out Result
	seen := map[string]bool{}
	_, split := cmd.(MarkDevicesOffline)
	for _, r := range rs {
		for _, d := range r.Devices {
			if !seen[d.ID] {
				seen[d.ID] = true
				out.Devices = append(out.Devices, d)
			}
		}
		if split {
			out.Count += r.Count
		} else {
			out.Count = max(out.Count, r.Count)
		}
	}
	sortDevices(out.Devices)
	return out
}
