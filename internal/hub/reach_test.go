// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

// partialReach applies commands on its store, as a master of a cluster of
// two whose other master is down: a write that takes access away reaches
// one of two.
type partialReach struct{ s *store.Store }

func (p partialReach) Apply(ctx context.Context, cmd store.Command) (store.Result, error) {
	res, err := p.s.ApplyLocal(ctx, cmd)
	if err == nil && store.TakesAccess(cmd) {
		res.Reach = &store.Reach{Applied: 1, Of: 2}
	}
	return res, err
}

// TestReachReported: a sign-out or a revocation some master has not taken
// yet answers 200 with how many did; one that reached every master, 204.
// A hub that could not compare sign-ins says so on its session.
func TestReachReported(t *testing.T) {
	uncompared := true
	f := newAPIFixture(t, false, func(c *Config) {
		st := storetest.Open(t, store.WithApplier(func(s *store.Store) store.Applier { return partialReach{s} }))
		pol := policy.New(st.Audit())
		if err := setAdminPassword(t.Context(), st, pol, "test", testPassword, testArgon); err != nil {
			t.Fatal(err)
		}
		c.Store, c.Policy = st, pol
		c.Registry = NewRegistry(RegistryConfig{Store: st, Log: c.Log})
		c.Uncompared = func() bool { return uncompared }
	})
	c := sessionCookie(t, f.login(t, testPassword))

	resp := f.do(t, http.MethodGet, "/api/v1/session", "", c)
	var sess SessionJSON
	if err := json.Unmarshal(resp.body, &sess); err != nil || !sess.Uncompared {
		t.Fatalf("session of a hub that could not compare sign-ins: %s, %v; want sign_ins_uncompared", resp.body, err)
	}
	uncompared = false
	resp = f.do(t, http.MethodGet, "/api/v1/session", "", c)
	sess = SessionJSON{}
	if err := json.Unmarshal(resp.body, &sess); err != nil || sess.Uncompared {
		t.Fatalf("session once compared: %s, %v", resp.body, err)
	}

	resp = f.do(t, http.MethodPost, "/api/v1/dashboard/tokens", `{"name": "wall"}`, c)
	var tok CreatedDashboardTokenJSON
	if resp.StatusCode != http.StatusCreated || json.Unmarshal(resp.body, &tok) != nil {
		t.Fatalf("create a dashboard token: %d %s", resp.StatusCode, resp.body)
	}
	id := tok.Token.ID
	for _, req := range []struct{ method, path string }{
		{http.MethodDelete, "/api/v1/dashboard/tokens/" + id},
		{http.MethodPost, "/api/v1/logout"},
	} {
		resp := f.do(t, req.method, req.path, "", c)
		var got ReachJSON
		if resp.StatusCode != http.StatusOK || json.Unmarshal(resp.body, &got) != nil ||
			got.Applied != 1 || got.Of != 2 || got.Message == "" {
			t.Fatalf("%s %s on 1 of 2 masters: %d %s; want 200 with the reach", req.method, req.path, resp.StatusCode, resp.body)
		}
	}
}
