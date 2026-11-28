// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// panelsSchema is the schema version whose migration (00022) added the
// panels and panel_links tables. Before it there are no panels, none can be
// saved, and no share link is valid.
const panelsSchema = 22

// Panel is a guest or kiosk panel: a name and its widgets, as the JSON the
// hub validated. The store keeps the widgets as they were given.
type Panel struct {
	ID        string
	Name      string
	Widgets   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// PanelLink is a share link of a panel, without its secret.
type PanelLink struct {
	ID        string
	PanelID   string
	CreatedAt time.Time
	// ExpiresAt is zero for a link that never expires.
	ExpiresAt time.Time
	// RevokedAt is zero for a link in use.
	RevokedAt time.Time
}

// Panels is the repository for panels and their share links. Callers pass a
// link's secret; only its SHA-256 hash is ever stored.
type Panels struct{ s *Store }

// Panels returns the panel repository.
func (s *Store) Panels() Panels { return Panels{s: s} }

// requireSchema refuses a write before schema 22. It runs before the
// proposal: a hub still on an older binary halts on a command it cannot
// decode.
func (r Panels) requireSchema(ctx context.Context) error {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return err
	}
	if v < panelsSchema {
		return fmt.Errorf("%w: it needs %d, the database is at %d; upgrade every hub of the cluster first",
			ErrSchemaTooOld, panelsSchema, v)
	}
	return nil
}

// Create stores a new panel. Before schema 22 it fails with ErrSchemaTooOld.
func (r Panels) Create(ctx context.Context, p Panel) error {
	if p.ID == "" || p.Name == "" || p.Widgets == "" {
		return errors.New("create panel: id, name and widgets are required")
	}
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("create panel: %w", err)
	}
	if _, err := r.s.apply(ctx, CreatePanel{
		ID: p.ID, Name: p.Name, Widgets: p.Widgets, At: toMillis(p.CreatedAt),
	}); err != nil {
		return fmt.Errorf("create panel %s: %w", p.ID, err)
	}
	return nil
}

// Update replaces the name and widgets of panel p.ID at time at. It fails with
// ErrNotFound when there is no such panel.
func (r Panels) Update(ctx context.Context, p Panel, at time.Time) error {
	if p.ID == "" || p.Name == "" || p.Widgets == "" {
		return errors.New("update panel: id, name and widgets are required")
	}
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("update panel: %w", err)
	}
	if _, err := r.s.apply(ctx, UpdatePanel{ID: p.ID, Name: p.Name, Widgets: p.Widgets, At: toMillis(at)}); err != nil {
		return fmt.Errorf("update panel %s: %w", p.ID, err)
	}
	return nil
}

// Delete deletes panel id and every share link of it. It fails with
// ErrNotFound when there is no such panel.
func (r Panels) Delete(ctx context.Context, id string) error {
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("delete panel: %w", err)
	}
	if _, err := r.s.apply(ctx, DeletePanel{ID: id}); err != nil {
		return fmt.Errorf("delete panel %s: %w", id, err)
	}
	return nil
}

// Get returns panel id, or ErrNotFound.
func (r Panels) Get(ctx context.Context, id string) (Panel, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return Panel{}, fmt.Errorf("get panel %s: %w", id, err)
	}
	if v < panelsSchema {
		return Panel{}, fmt.Errorf("get panel %s: %w", id, ErrNotFound)
	}
	p, err := scanPanel(r.s.queryRowLive(ctx, "panels", id, panelColumns, ` FROM panels WHERE id = ?`+notStub, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Panel{}, fmt.Errorf("get panel %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return Panel{}, fmt.Errorf("get panel %s: %w", id, err)
	}
	return p, nil
}

// List returns every panel, by name. Before schema 22 there are none.
func (r Panels) List(ctx context.Context) ([]Panel, error) {
	out, err := r.query(ctx, gather{order: then(byText(1), byText(0))}, `TRUE`, `ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("list panels: %w", err)
	}
	return out, nil
}

// query returns the live panels matching where, then tail (an ORDER BY
// clause). The clauses are constants of this file's callers; values are
// bound.
func (r Panels) query(ctx context.Context, g gather, where, tail string, args ...any) ([]Panel, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil || v < panelsSchema {
		return nil, err
	}
	rest := ` FROM panels WHERE (` + where + `)` + notStub +
		liveOnly(v >= VersionedSchema) + ` ` + tail
	g.table = "panels"
	rows, err := r.s.list(ctx, "", g, panelColumns, rest, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Panel
	for rows.Next() {
		p, err := scanPanel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

const panelColumns = `SELECT id, name, widgets, created_at, updated_at`

// notStub is the condition, ANDed into a read of panels, that skips the
// stubs RevokePanelLink writes: a real panel's widgets are never empty.
const notStub = ` AND widgets <> ''`

// stubHLC is the version of a panel stub: older than any version of a real
// panel, so the real row, from a master that has it, always wins the merge.
const stubHLC = 1

// livePanel returns the live, real panel id a command reads, or nil if
// there is none or only its stub.
func livePanel(ctx context.Context, w *writer, id string) (row, error) {
	p, err := w.get(ctx, "panels", id)
	if err != nil || p == nil || p.str("widgets") == "" {
		return nil, err
	}
	return p, nil
}

// scanPanel scans panelColumns.
func scanPanel(row rowScanner) (Panel, error) {
	var (
		p                Panel
		created, updated int64
	)
	if err := row.Scan(&p.ID, &p.Name, &p.Widgets, &created, &updated); err != nil {
		return Panel{}, err
	}
	p.CreatedAt, p.UpdatedAt = fromMillis(created), fromMillis(updated)
	return p, nil
}

// CreateLink stores share link l of panel l.PanelID by the hash of secret. It
// fails with ErrNotFound when there is no such panel.
func (r Panels) CreateLink(ctx context.Context, l PanelLink, secret string) error {
	if l.ID == "" || l.PanelID == "" || secret == "" {
		return errors.New("create panel link: id, panel and secret are required")
	}
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("create panel link: %w", err)
	}
	h := hashSecret(secret)
	cmd := CreatePanelLink{ID: l.ID, PanelID: l.PanelID, Hash: h[:], CreatedAt: toMillis(l.CreatedAt)}
	if !l.ExpiresAt.IsZero() {
		exp := toMillis(l.ExpiresAt)
		cmd.ExpiresAt = &exp
	}
	if _, err := r.s.apply(ctx, cmd); err != nil {
		return fmt.Errorf("create link of panel %s: %w", l.PanelID, err)
	}
	return nil
}

// RevokeLink revokes link id of panel panelID at time at. It fails with
// ErrNotFound when the panel has no such link in use.
func (r Panels) RevokeLink(ctx context.Context, panelID, id string, at time.Time) error {
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("revoke panel link: %w", err)
	}
	if _, err := r.s.apply(ctx, RevokePanelLink{PanelID: panelID, ID: id, At: toMillis(at)}); err != nil {
		return fmt.Errorf("revoke link %s of panel %s: %w", id, panelID, err)
	}
	return nil
}

// Links returns every share link, revoked and expired ones included, oldest
// first. Before schema 22 there are none.
func (r Panels) Links(ctx context.Context) ([]PanelLink, error) {
	out, err := r.queryLinks(ctx, gather{order: then(byInt(2), byText(0))}, `TRUE`, `ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("list panel links: %w", err)
	}
	return out, nil
}

// CheckLink returns the panel and link whose secret is secret, if the link
// is usable at now. It fails with ErrNotFound for an unknown secret (and
// before schema 22), ErrTokenRevoked for a revoked link and ErrTokenExpired
// for an expired one.
func (r Panels) CheckLink(ctx context.Context, secret string, now time.Time) (Panel, PanelLink, error) {
	h := hashSecret(secret)
	links, err := r.queryLinks(ctx, gather{}, `hash = ?`, ``, h[:])
	if err != nil {
		return Panel{}, PanelLink{}, fmt.Errorf("check panel link: %w", err)
	}
	if len(links) == 0 {
		return Panel{}, PanelLink{}, fmt.Errorf("check panel link: %w", ErrNotFound)
	}
	l := links[0]
	switch {
	case !l.RevokedAt.IsZero():
		return Panel{}, PanelLink{}, fmt.Errorf("check panel link %s: %w", l.ID, ErrTokenRevoked)
	case !l.ExpiresAt.IsZero() && !now.Before(l.ExpiresAt):
		return Panel{}, PanelLink{}, fmt.Errorf("check panel link %s: %w", l.ID, ErrTokenExpired)
	}
	p, err := r.Get(ctx, l.PanelID)
	if err != nil {
		return Panel{}, PanelLink{}, fmt.Errorf("check panel link %s: %w", l.ID, err)
	}
	return p, l, nil
}

// queryLinks returns the live share links matching where, then tail, as
// query does.
func (r Panels) queryLinks(ctx context.Context, g gather, where, tail string, args ...any) ([]PanelLink, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil || v < panelsSchema {
		return nil, err
	}
	rest := ` FROM panel_links WHERE (` + where + `)` +
		liveOnly(v >= VersionedSchema) + ` ` + tail
	g.table = "panel_links"
	rows, err := r.s.list(ctx, "", g, `SELECT id, panel_id, created_at, expires_at, revoked_at`, rest, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PanelLink
	for rows.Next() {
		var (
			l                PanelLink
			created          int64
			expires, revoked sql.NullInt64
		)
		if err := rows.Scan(&l.ID, &l.PanelID, &created, &expires, &revoked); err != nil {
			return nil, err
		}
		l.CreatedAt = fromMillis(created)
		if expires.Valid {
			l.ExpiresAt = fromMillis(expires.Int64)
		}
		if revoked.Valid {
			l.RevokedAt = fromMillis(revoked.Int64)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// CreatePanel inserts a panel; its widgets are the JSON the hub validated.
type CreatePanel struct {
	Stamp
	ID      string `json:"id"`
	Name    string `json:"name"`
	Widgets string `json:"widgets"`
	At      int64  `json:"at"`
}

// Op implements Command.
func (CreatePanel) Op() string { return "create_panel" }

func (CreatePanel) minSchema() int64 { return panelsSchema }

func (c CreatePanel) apply(ctx context.Context, w *writer) (Result, error) {
	return Result{}, w.insert(ctx, "panels", row{
		"id": c.ID, "name": c.Name, "widgets": c.Widgets, "created_at": c.At, "updated_at": c.At,
	})
}

// UpdatePanel replaces a panel's name and widgets; ErrNotFound if there is
// no such panel.
type UpdatePanel struct {
	Stamp
	ID      string `json:"id"`
	Name    string `json:"name"`
	Widgets string `json:"widgets"`
	At      int64  `json:"at"`
}

// Op implements Command.
func (UpdatePanel) Op() string { return "update_panel" }

func (UpdatePanel) minSchema() int64 { return panelsSchema }

func (c UpdatePanel) apply(ctx context.Context, w *writer) (Result, error) {
	r, err := livePanel(ctx, w, c.ID)
	if err != nil {
		return Result{}, err
	}
	if r == nil {
		return Result{}, ErrNotFound
	}
	r["name"], r["widgets"], r["updated_at"] = c.Name, c.Widgets, c.At
	return Result{Count: 1}, w.put(ctx, "panels", r)
}

// DeletePanel deletes a panel and its share links; ErrNotFound if there is
// no such panel.
type DeletePanel struct {
	Stamp
	ID string `json:"id"`
}

// Op implements Command.
func (DeletePanel) Op() string { return "delete_panel" }

func (DeletePanel) minSchema() int64 { return panelsSchema }

func (c DeletePanel) apply(ctx context.Context, w *writer) (Result, error) {
	if p, err := livePanel(ctx, w, c.ID); err != nil || p == nil {
		if err == nil {
			err = ErrNotFound
		}
		return Result{}, err
	}
	// The links go first, so the result does not depend on foreign keys
	// being enforced.
	if err := deleteWhere(ctx, w, "panel_links", `panel_id = ?`, c.ID); err != nil {
		return Result{}, err
	}
	return deleteRow(ctx, w, "panels", c.ID)
}

// CreatePanelLink inserts a share link by its hash; ErrNotFound if there is
// no such panel.
type CreatePanelLink struct {
	Stamp
	ID        string `json:"id"`
	PanelID   string `json:"panel_id"`
	Hash      []byte `json:"hash"`
	CreatedAt int64  `json:"created_at"`
	// ExpiresAt is nil for a link that never expires.
	ExpiresAt *int64 `json:"expires_at,omitempty"`
}

// Op implements Command.
func (CreatePanelLink) Op() string { return "create_panel_link" }

func (CreatePanelLink) minSchema() int64 { return panelsSchema }

func (c CreatePanelLink) apply(ctx context.Context, w *writer) (Result, error) {
	p, err := livePanel(ctx, w, c.PanelID)
	if err != nil {
		return Result{}, err
	}
	if p == nil {
		return Result{}, ErrNotFound
	}
	return Result{}, w.insert(ctx, "panel_links", row{
		"id": c.ID, "panel_id": c.PanelID, "hash": c.Hash, "created_at": c.CreatedAt,
		"expires_at": optInt(c.ExpiresAt), "revoked_at": nil,
	})
}

// RevokePanelLink revokes a panel's share link in use; ErrNotFound if the
// panel has no such link in use.
type RevokePanelLink struct {
	Stamp
	PanelID string `json:"panel_id"`
	ID      string `json:"id"`
	At      int64  `json:"at"`
}

// Op implements Command.
func (RevokePanelLink) Op() string { return "revoke_panel_link" }

func (RevokePanelLink) minSchema() int64 { return panelsSchema }

func (c RevokePanelLink) apply(ctx context.Context, w *writer) (Result, error) {
	p, err := w.getAny(ctx, "panels", c.PanelID)
	switch {
	case err != nil:
		return Result{}, err
	case p == nil && w.versioned && w.s.Sharded():
		// Both the panel and the link were made while this master was
		// down (#389). A link's stub needs a panel row (the foreign key):
		// write a stub of the panel too.
		if err := stubPanel(ctx, w, c.PanelID, c.At); err != nil {
			return Result{}, err
		}
	case p == nil || p.deleted():
		// A hub alone holds every panel; a deleted one has no links.
		return Result{}, ErrNotFound
	}
	return revokeOrStub(ctx, w, "panel_links", `id = ? AND panel_id = ?`, c.At, row{
		"id": c.ID, "panel_id": c.PanelID, "created_at": c.At,
	}, c.ID, c.PanelID)
}

// stubPanel writes a stub of panel id, which this master does not hold, so
// a link's revoked stub has a panel row to point at. The stub has no name
// and no widgets, so no read shows it (notStub) and no command takes it for
// a panel (livePanel), and it is versioned stubHLC, so the real panel's row
// replaces it. It is a live row, not a tombstone: a tombstone that old
// would be collected at once, and the link's stub with it (ON DELETE
// CASCADE). It goes to the other masters before the link's stub, so one
// that lacks the panel too can take the link's.
func stubPanel(ctx context.Context, w *writer, id string, at int64) error {
	m := Mutation{
		Table: "panels", Row: row{"id": id, "name": "", "widgets": "", "created_at": at, "updated_at": at},
		HLC: stubHLC, Origin: w.stamp.Origin,
	}
	if err := w.dt.merge(ctx, w.tx, m, func() error {
		_, err := mergeRow(ctx, w.s, w.tx, m, w.versioned)
		return err
	}); err != nil {
		return err
	}
	w.muts = append(w.muts, m)
	return nil
}
