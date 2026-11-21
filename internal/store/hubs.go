// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrUnavailable is returned by a replicated Applier that cannot reach a
// cluster leader in time, or whose leader changed while it applied a write:
// the write may be retried.
var ErrUnavailable = errors.New("cluster unavailable: no leader reachable")

// Hubs is the repository for cluster hub metadata: the agent-facing URL of
// each hub, keyed by its cluster node ID.
type Hubs struct{ s *Store }

// Hubs returns the cluster hub repository.
func (s *Store) Hubs() Hubs { return Hubs{s: s} }

// SetAgentURL records the agent-facing URL of hub nodeID.
func (r Hubs) SetAgentURL(ctx context.Context, nodeID, agentURL string) error {
	if _, err := r.s.apply(ctx, SetHubURL{NodeID: nodeID, AgentURL: agentURL}); err != nil {
		return fmt.Errorf("set agent URL of hub %s: %w", nodeID, err)
	}
	return nil
}

// AgentURLs returns the recorded agent-facing URL of every hub by node ID.
func (r Hubs) AgentURLs(ctx context.Context) (map[string]string, error) {
	rows, err := r.s.db.QueryContext(ctx, `SELECT node_id, agent_url FROM cluster_hubs`)
	if err != nil {
		return nil, fmt.Errorf("list hub URLs: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, u string
		if err := rows.Scan(&id, &u); err != nil {
			return nil, fmt.Errorf("list hub URLs: %w", err)
		}
		out[id] = u
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list hub URLs: %w", err)
	}
	return out, nil
}

// RecordCert records the hub node certificate serial issued to nodeID. A
// serial already recorded, revoked or not, is left as it is.
func (r Hubs) RecordCert(ctx context.Context, serial, nodeID string) error {
	if serial == "" || nodeID == "" {
		return errors.New("record hub cert: serial and node ID are required")
	}
	if _, err := r.s.apply(ctx, RecordHubCert{Serial: serial, NodeID: nodeID}); err != nil {
		return fmt.Errorf("record hub cert %s of %s: %w", serial, nodeID, err)
	}
	return nil
}

// RevokeCerts revokes every recorded, unrevoked certificate of hub nodeID at
// now and returns how many it revoked.
func (r Hubs) RevokeCerts(ctx context.Context, nodeID string, now time.Time) (int, error) {
	res, err := r.s.apply(ctx, RevokeHubCerts{NodeID: nodeID, Now: toMillis(now)})
	if err != nil {
		return 0, fmt.Errorf("revoke certs of hub %s: %w", nodeID, err)
	}
	return res.Count, nil
}

// hubCertsSchema is the schema version whose migration (00006) added the
// hub_certs table. A newer binary runs on an older cluster database until
// every hub of the cluster is upgraded; before this version there is no deny list.
const hubCertsSchema = 6

// RequireCerts returns ErrSchemaTooOld if the database is at a schema before
// hub certificates were recorded: nothing can be recorded or revoked until
// the cluster migrates.
func (r Hubs) RequireCerts(ctx context.Context) error {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return fmt.Errorf("hub certs: %w", err)
	}
	if v < hubCertsSchema {
		return fmt.Errorf("hub certs: %w: they need %d, the database is at %d; upgrade every hub of the cluster first",
			ErrSchemaTooOld, hubCertsSchema, v)
	}
	return nil
}

// CheckCert returns ErrCertRevoked if the hub certificate with serial was
// revoked. A serial that was never recorded is not an error: hub
// certificates are refused by revocation, not admitted by a list. Before
// the schema that records them, no hub certificate is revoked.
func (r Hubs) CheckCert(ctx context.Context, serial string) error {
	if err := r.RequireCerts(ctx); errors.Is(err, ErrSchemaTooOld) {
		return nil
	} else if err != nil {
		return fmt.Errorf("check hub cert %s: %w", serial, err)
	}
	var revoked bool
	err := r.s.db.QueryRowContext(ctx,
		`SELECT revoked_at IS NOT NULL FROM hub_certs WHERE serial = ?`, serial).Scan(&revoked)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("check hub cert %s: %w", serial, err)
	case revoked:
		return fmt.Errorf("check hub cert %s: %w", serial, ErrCertRevoked)
	}
	return nil
}

// HubCert is a recorded hub node certificate.
type HubCert struct {
	Serial  string
	NodeID  string
	Revoked bool
	// Fingerprint and CAFP are the SHA-256 of the certificate and of the
	// CA that issued it, as pki.FingerprintHex; empty when not recorded,
	// as before CertPinsSchema.
	Fingerprint string
	CAFP        string
}

// Certs returns the certificates recorded for hub nodeID, ordered by serial:
// none before the schema that records them.
func (r Hubs) Certs(ctx context.Context, nodeID string) ([]HubCert, error) {
	if err := r.RequireCerts(ctx); errors.Is(err, ErrSchemaTooOld) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("list certs of hub %s: %w", nodeID, err)
	}
	fps := `'', ''`
	if ok, err := atSchema(ctx, r.s.db, CertPinsSchema); err != nil {
		return nil, fmt.Errorf("list certs of hub %s: %w", nodeID, err)
	} else if ok {
		fps = `COALESCE(fingerprint, ''), COALESCE(ca_fp, '')`
	}
	rows, err := r.s.db.QueryContext(ctx, `SELECT serial, node_id, revoked_at IS NOT NULL, `+fps+
		` FROM hub_certs WHERE node_id = ? ORDER BY serial`, nodeID)
	if err != nil {
		return nil, fmt.Errorf("list certs of hub %s: %w", nodeID, err)
	}
	defer rows.Close()
	var out []HubCert
	for rows.Next() {
		var c HubCert
		if err := rows.Scan(&c.Serial, &c.NodeID, &c.Revoked, &c.Fingerprint, &c.CAFP); err != nil {
			return nil, fmt.Errorf("list certs of hub %s: %w", nodeID, err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list certs of hub %s: %w", nodeID, err)
	}
	return out, nil
}
