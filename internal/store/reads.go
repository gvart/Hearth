// SPDX-License-Identifier: AGPL-3.0-only

package store

import "strings"

// Reads inside writes in a sharded cluster (#276).
//
// A command reads the rows it decides on (is the token used, is the
// certificate pinned, which certificates does the device have) from the
// database of the member that applies it. That member is a replica of the
// rows, but it may have missed a write made while it was down: the write
// went to the others and waits in a hint, or in anti-entropy. For the
// commands below, a stale or missing copy changes the outcome, so the
// member that applies one first fetches the rows it reads from the other
// live replicas and merges them (see ReadsOf); the command then decides on
// the newest copy any reachable replica has.

// Read is a set of rows a command reads before it writes: the row of Table
// with primary key Key, or, Key nil, the rows Where (with Args) matches.
// Where only tests columns a row never changes, so a replica's answer
// names every row the command could read.
type Read struct {
	Table string
	Key   Values
	Where string
	Args  Values
}

// Ref returns the row a keyed read names.
func (r Read) Ref() (RowRef, bool) {
	if r.Key == nil {
		return RowRef{}, false
	}
	return RowRef{Table: r.Table, Key: r.Key}, true
}

// KeysQuery is the query that selects the keys of the rows r matches,
// tombstones included, in the table's key order.
func (r Read) KeysQuery() string {
	// Table and Where are constants of ReadsOf.
	return `SELECT ` + strings.Join(keyCols(r.Table), `, `) + ` FROM ` + r.Table + ` WHERE ` + r.Where
}

// ReadsOf returns the rows cmd reads whose newest copy decides its outcome,
// so the member applying it in a sharded cluster fetches them first; nil
// for a command whose outcome a stale copy does not change. A certificate
// read brings its device, the row it references.
func ReadsOf(cmd Command) []Read {
	key := func(table string, k ...any) Read { return Read{Table: table, Key: k} }
	switch c := cmd.(type) {
	case PinCert:
		// A missing copy refuses a known certificate; an unpinned one pins
		// a second fingerprint over the first.
		return []Read{key("devices", c.DeviceID), key("certs", c.Serial)}
	case RevokeDevice:
		// A certificate the member missed would stay valid.
		return []Read{key("devices", c.DeviceID), {Table: "certs", Where: `device_id = ?`, Args: Values{c.DeviceID}}}
	case RevokeHubCerts:
		return []Read{{Table: "hub_certs", Where: `node_id = ?`, Args: Values{c.NodeID}}}
	case ConsumeToken:
		return []Read{key("tokens", c.Hash)}
	case ConsumeJoinToken:
		return []Read{key("join_tokens", c.Hash)}
	case UseApprovalLink:
		return []Read{key("approval_links", c.Hash)}
	case DecideApproval:
		// An expiry over a copy still pending would replace the owner's
		// decision.
		return []Read{key("approvals", c.ID)}
	case DeleteSession:
		// The newest copy is deleted (a missing one gets a tombstone all
		// the same).
		return []Read{key("sessions", c.Hash)}
	case SetPasswordHash:
		// Every session ends, and the epoch rises past the newest one (a
		// session this master missed ends by the epoch all the same).
		return []Read{{Table: "admin", Where: `id = 1`}, {Table: "sessions", Where: `1 = 1`}}
	case DeletePanel:
		// Its links go with it, those another master holds too.
		return []Read{key("panels", c.ID), {Table: "panel_links", Where: `panel_id = ?`, Args: Values{c.ID}}}
	case CreateMCPToken:
		// Its name is the key: a missed token would be replaced, not
		// refused as existing.
		return []Read{key("mcp_tokens", c.Name)}
	case RevokeMCPToken:
		return []Read{key("mcp_tokens", c.Name)}
	case RevokeDashboardToken:
		return []Read{key("dashboard_tokens", c.ID)}
	case RevokePanelLink:
		return []Read{key("panels", c.PanelID), key("panel_links", c.ID)}
	case CreatePanelLink:
		return []Read{key("panels", c.PanelID)}
	case StartCARotation:
		// Two rotations at once: each started over a copy without the other.
		return []Read{{Table: "ca_rotations", Where: `1 = 1`}}
	case AdvanceCARotation:
		reads := []Read{key("ca_rotations", c.NewCAFP)}
		if c.To == CAStageAborted {
			reads = append(reads, Read{Table: "hub_certs", Where: `ca_fp = ?`, Args: Values{c.NewCAFP}})
		}
		return reads
	case ResealSecrets:
		reads := []Read{key("ca_rotations", c.NewCAFP)}
		for _, s := range c.Secrets {
			if _, ok := sealedColumns[s.Table]; ok {
				reads = append(reads, key(s.Table, s.ID))
			}
		}
		return reads
	case PutConfigDocs:
		if c.IfNone {
			// The first import, refused if any document is stored.
			return []Read{{Table: "config_docs", Where: `1 = 1`}}
		}
	case CreateRunbookRun:
		// It counts the runbook's unresolved runs; and reading them from a
		// majority of the masters proves one is reachable before the run is
		// written here (#307, #387).
		return []Read{{Table: "runbook_runs", Where: `runbook_id = ? AND finished_at = 0`, Args: Values{c.RunbookID}}}
	case SaveRunbookRun:
		// A copy behind the newest refuses the newest version as a conflict,
		// and takes a save from the version it holds over the newer ones.
		return []Read{key("runbook_runs", c.ID)}
	case DeleteConfigDoc:
		return []Read{key("config_docs", ConfigDocID(c.Kind, c.Name))}
	case PutAuditKey:
		// A copy without the key would store it again.
		return []Read{key("audit_keys", c.ID)}
	}
	return nil
}
