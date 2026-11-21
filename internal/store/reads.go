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
		// A missing copy writes no tombstone: the session stays valid.
		return []Read{key("sessions", c.Hash)}
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
	case DeleteConfigDoc:
		return []Read{key("config_docs", ConfigDocID(c.Kind, c.Name))}
	}
	return nil
}
