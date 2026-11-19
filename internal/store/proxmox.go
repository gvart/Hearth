// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// proxmoxServersSchema is the schema version whose migration (00015) added
// the proxmox_servers table. A newer binary runs on an older cluster database
// until `hearth cluster migrate`; before this version no server can be added.
const proxmoxServersSchema = 15

// ProxmoxServer is a Proxmox VE server adopted through an API token.
type ProxmoxServer struct {
	ID   string
	Name string
	// Sealed is the encrypted connection. The store never sees it in the clear.
	Sealed    []byte
	CreatedAt time.Time
}

// AddProxmoxServer stores a server and its sealed connection. A duplicate ID
// or name is a constraint violation.
type AddProxmoxServer struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Sealed    []byte `json:"sealed"`
	CreatedAt int64  `json:"created_at"`
}

// Op implements Command.
func (AddProxmoxServer) Op() string { return "add_proxmox_server" }

func (AddProxmoxServer) minSchema() int64 { return proxmoxServersSchema }

func (c AddProxmoxServer) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO proxmox_servers (id, name, connection, created_at) VALUES (?, ?, ?, ?)`,
		c.ID, c.Name, c.Sealed, c.CreatedAt)
	return Result{}, err
}

// RemoveProxmoxServer deletes a server. It fails with ErrNotFound if there is
// none with ID.
type RemoveProxmoxServer struct {
	ID string `json:"id"`
}

// Op implements Command.
func (RemoveProxmoxServer) Op() string { return "remove_proxmox_server" }

func (RemoveProxmoxServer) minSchema() int64 { return proxmoxServersSchema }

func (c RemoveProxmoxServer) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	res, err := tx.ExecContext(ctx, `DELETE FROM proxmox_servers WHERE id = ?`, c.ID)
	if err != nil {
		return Result{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Result{}, err
	}
	if n == 0 {
		return Result{}, ErrNotFound
	}
	return Result{Count: int(n)}, nil
}

// ProxmoxServers is the repository for adopted Proxmox VE servers.
type ProxmoxServers struct{ s *Store }

// ProxmoxServers returns the Proxmox server repository.
func (s *Store) ProxmoxServers() ProxmoxServers { return ProxmoxServers{s: s} }

// Add stores c. Its connection must already be sealed.
func (r ProxmoxServers) Add(ctx context.Context, c ProxmoxServer) error {
	if c.ID == "" || c.Name == "" || len(c.Sealed) == 0 {
		return errors.New("add proxmox server: ID, name and sealed connection are required")
	}
	if _, err := r.s.apply(ctx, AddProxmoxServer{
		ID: c.ID, Name: c.Name, Sealed: c.Sealed, CreatedAt: toMillis(c.CreatedAt),
	}); err != nil {
		return fmt.Errorf("add proxmox server %s: %w", c.Name, err)
	}
	return nil
}

// Remove deletes server id, or fails with ErrNotFound.
func (r ProxmoxServers) Remove(ctx context.Context, id string) error {
	if _, err := r.s.apply(ctx, RemoveProxmoxServer{ID: id}); err != nil {
		return fmt.Errorf("remove proxmox server %s: %w", id, err)
	}
	return nil
}

// List returns every server ordered by name. Before the schema that added
// them there are none.
func (r ProxmoxServers) List(ctx context.Context) ([]ProxmoxServer, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return nil, fmt.Errorf("list proxmox servers: %w", err)
	}
	if v < proxmoxServersSchema {
		return nil, nil
	}
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT id, name, connection, created_at FROM proxmox_servers ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list proxmox servers: %w", err)
	}
	defer rows.Close()
	var out []ProxmoxServer
	for rows.Next() {
		var (
			c  ProxmoxServer
			ms int64
		)
		if err := rows.Scan(&c.ID, &c.Name, &c.Sealed, &ms); err != nil {
			return nil, fmt.Errorf("list proxmox servers: %w", err)
		}
		c.CreatedAt = fromMillis(ms)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list proxmox servers: %w", err)
	}
	return out, nil
}
