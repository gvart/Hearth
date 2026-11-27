// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// opnsenseFirewallsSchema is the schema version whose migration (00038) added
// the opnsense_firewalls table. A newer binary runs on an older cluster database
// until every hub of the cluster is upgraded; before this version no firewall
// can be adopted.
const opnsenseFirewallsSchema = 38

// OPNsenseFirewall is an OPNsense firewall adopted through its REST API.
type OPNsenseFirewall struct {
	ID   string
	Name string
	// Sealed is the encrypted connection. The store never sees it in the clear.
	Sealed    []byte
	CreatedAt time.Time
}

// AddOPNsenseFirewall stores a firewall and its sealed connection. A duplicate ID
// or name is a constraint violation.
type AddOPNsenseFirewall struct {
	Stamp
	ID        string `json:"id"`
	Name      string `json:"name"`
	Sealed    []byte `json:"sealed"`
	CreatedAt int64  `json:"created_at"`
}

// Op implements Command.
func (AddOPNsenseFirewall) Op() string { return "add_opnsense_firewall" }

func (AddOPNsenseFirewall) minSchema() int64 { return opnsenseFirewallsSchema }

func (c AddOPNsenseFirewall) apply(ctx context.Context, w *writer) (Result, error) {
	return Result{}, w.insert(ctx, "opnsense_firewalls", row{
		"id": c.ID, "name": c.Name, "connection": c.Sealed, "created_at": c.CreatedAt,
	})
}

// RemoveOPNsenseFirewall deletes a firewall. It fails with ErrNotFound if there is
// none with ID.
type RemoveOPNsenseFirewall struct {
	Stamp
	ID string `json:"id"`
}

// Op implements Command.
func (RemoveOPNsenseFirewall) Op() string { return "remove_opnsense_firewall" }

func (RemoveOPNsenseFirewall) minSchema() int64 { return opnsenseFirewallsSchema }

func (c RemoveOPNsenseFirewall) apply(ctx context.Context, w *writer) (Result, error) {
	return deleteRow(ctx, w, "opnsense_firewalls", c.ID)
}

// OPNsenseFirewalls is the repository for adopted OPNsense firewalls.
type OPNsenseFirewalls struct{ s *Store }

// OPNsenseFirewalls returns the OPNsense firewall repository.
func (s *Store) OPNsenseFirewalls() OPNsenseFirewalls { return OPNsenseFirewalls{s: s} }

// requireSchema refuses a write before the schema that added the table. It
// runs before the proposal: a hub still on an older binary halts on a command
// it cannot decode.
func (r OPNsenseFirewalls) requireSchema(ctx context.Context) error {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return err
	}
	if v < opnsenseFirewallsSchema {
		return fmt.Errorf("%w: it needs %d, the database is at %d; upgrade every hub of the cluster first",
			ErrSchemaTooOld, opnsenseFirewallsSchema, v)
	}
	return nil
}

// Add stores c. Its connection must already be sealed. Before schema 38 it
// fails with ErrSchemaTooOld.
func (r OPNsenseFirewalls) Add(ctx context.Context, c OPNsenseFirewall) error {
	if c.ID == "" || c.Name == "" || len(c.Sealed) == 0 {
		return errors.New("add opnsense firewall: ID, name and sealed connection are required")
	}
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("add opnsense firewall %s: %w", c.Name, err)
	}
	if _, err := r.s.apply(ctx, AddOPNsenseFirewall{
		ID: c.ID, Name: c.Name, Sealed: c.Sealed, CreatedAt: toMillis(c.CreatedAt),
	}); err != nil {
		return fmt.Errorf("add opnsense firewall %s: %w", c.Name, err)
	}
	return nil
}

// Remove deletes firewall id, or fails with ErrNotFound. Before schema 38 it
// fails with ErrSchemaTooOld.
func (r OPNsenseFirewalls) Remove(ctx context.Context, id string) error {
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("remove opnsense firewall %s: %w", id, err)
	}
	if _, err := r.s.apply(ctx, RemoveOPNsenseFirewall{ID: id}); err != nil {
		return fmt.Errorf("remove opnsense firewall %s: %w", id, err)
	}
	return nil
}

// List returns every firewall ordered by name. Before the schema that added
// them there are none.
func (r OPNsenseFirewalls) List(ctx context.Context) ([]OPNsenseFirewall, error) {
	ok, err := atSchema(ctx, r.s.db, opnsenseFirewallsSchema)
	if err != nil {
		return nil, fmt.Errorf("list opnsense firewalls: %w", err)
	}
	if !ok {
		return nil, nil
	}
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT id, name, connection, created_at FROM opnsense_firewalls WHERE _deleted = 0 ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list opnsense firewalls: %w", err)
	}
	defer rows.Close()
	var out []OPNsenseFirewall
	for rows.Next() {
		var (
			c  OPNsenseFirewall
			ms int64
		)
		if err := rows.Scan(&c.ID, &c.Name, &c.Sealed, &ms); err != nil {
			return nil, fmt.Errorf("list opnsense firewalls: %w", err)
		}
		c.CreatedAt = fromMillis(ms)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list opnsense firewalls: %w", err)
	}
	return out, nil
}
