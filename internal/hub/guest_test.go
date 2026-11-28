// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

// gatedShards is a cluster of one member, which holds every row, whose
// master rows are not ready while closed: the store's reads of sessions,
// tokens, panels and links fail with store.ErrUnavailable, as on a master
// still comparing them with the others (#384).
type gatedShards struct {
	st     *store.Store
	closed atomic.Bool
}

func (g *gatedShards) Holds(string) bool { return true }

func (g *gatedShards) ReadKey(ctx context.Context, _, q string, args store.Values) (store.Rows, error) {
	return g.st.ReadLocal(ctx, q, args)
}

func (g *gatedShards) ReadReplicas(ctx context.Context, _, q string, args store.Values) ([]store.Rows, error) {
	return g.ReadAll(ctx, q, args)
}

func (g *gatedShards) ReadAll(ctx context.Context, q string, args store.Values) ([]store.Rows, error) {
	rows, err := g.st.ReadLocal(ctx, q, args)
	if err != nil {
		return nil, err
	}
	return []store.Rows{rows}, nil
}

func (g *gatedShards) Repair([]store.RowRef) {}

func (g *gatedShards) MasterRowsReady() error {
	if g.closed.Load() {
		return store.ErrUnavailable
	}
	return nil
}

// newGatedFixture is a panel fixture on a store behind a gatedShards.
func newGatedFixture(t *testing.T) (*panelFixture, *gatedShards) {
	t.Helper()
	g := &gatedShards{}
	g.st = storetest.Open(t, store.WithShards(g))
	f := newPanelFixture(t, func(c *Config) {
		c.Store, c.Policy = g.st, policy.New(g.st.Audit())
		c.Registry = NewRegistry(RegistryConfig{Store: g.st, Log: c.Log})
	})
	f.st = g.st
	return f, g
}

// TestGuestLinkUnavailable: while this master may not read its share links
// yet, a guest request answers 503 cluster_unavailable, not 404 (the link
// may well be valid) nor 500, and runs nothing.
func TestGuestLinkUnavailable(t *testing.T) {
	f, g := newGatedFixture(t)
	ctx := t.Context()
	now := time.Now()
	if err := f.st.Panels().Create(ctx, store.Panel{ID: "p", Name: "Hall", Widgets: `[]`, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.Panels().CreateLink(ctx, store.PanelLink{ID: "l", PanelID: "p", CreatedAt: now}, "link-secret"); err != nil {
		t.Fatal(err)
	}
	if r := f.raw(t, http.MethodGet, "/api/v1/guest/link-secret", "", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("guest view with the gate open = %d %s", r.StatusCode, r.body)
	}

	g.closed.Store(true)
	action := `{"widget": "w", "action": "a"}`
	for _, req := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/guest/link-secret", ""},
		{http.MethodGet, "/api/v1/guest/link-secret/events", ""},
		{http.MethodPost, "/api/v1/guest/link-secret/actions", action},
	} {
		t.Run(req.method+" "+req.path, func(t *testing.T) {
			r := f.raw(t, req.method, req.path, req.body, nil)
			if r.StatusCode != http.StatusServiceUnavailable || decode[ErrorJSON](t, r).Code != "cluster_unavailable" {
				t.Fatalf("status = %d %s, want 503 cluster_unavailable", r.StatusCode, r.body)
			}
		})
	}
	// The page is plain text: it must not tell the guest the link is gone.
	if r := f.raw(t, http.MethodGet, "/p/link-secret", "", nil); r.StatusCode != http.StatusServiceUnavailable ||
		strings.Contains(string(r.body), "revoked") {
		t.Errorf("page = %d %s, want 503", r.StatusCode, r.body)
	}
	if runs := f.runner.runs(); len(runs) != 0 {
		t.Fatalf("ran %v", runs)
	}
}
