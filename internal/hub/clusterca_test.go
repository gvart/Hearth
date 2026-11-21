// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

var (
	errFakeOwner = errors.New("another master drives the hub CA rotation: master hub-a started it and is alive")
	errFakeDown  = errors.New("finish the hub CA rotation: these members are down: hub-c")
)

// fakeClusterCA runs the steps through the hub's policy engine, as the AP
// node does: a refusal is a denial once the precheck passes.
type fakeClusterCA struct {
	pol *policy.Engine
	mu  sync.Mutex
	// refuse refuses every step before it runs; fail fails it as it runs.
	refuse, fail error
	steps        []string
}

func (f *fakeClusterCA) CAStatus(context.Context) (ClusterCAJSON, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := ClusterCAJSON{NodeID: "hub-a", Hubs: []MemberCAJSON{{ID: "hub-a", Master: true, Serving: "aaaa"}}}
	if len(f.steps) > 0 {
		st.Rotation = &CARotationJSON{NewCAFP: "bbbb", Stage: "started", Active: true, Owner: "hub-a", OwnerAlive: true}
	}
	return st, nil
}

func (f *fakeClusterCA) ChangeCA(ctx context.Context, op, kind, id string, precheck func(context.Context) error) error {
	action := map[string]policy.Action{"rotate": policy.ClusterCARotate, "finish": policy.ClusterCAFinish, "abort": policy.ClusterCAAbort}[op]
	req := policy.Request{ActorKind: kind, ActorID: id, Action: action, Target: "hub CA", Precheck: precheck}
	if f.refuse != nil {
		req.Precheck = func(ctx context.Context) error {
			if err := precheck(ctx); err != nil {
				return err
			}
			return fmt.Errorf("%w (%w)", f.refuse, policy.ErrDenied)
		}
	}
	return f.pol.Do(ctx, req, func(context.Context) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.steps = append(f.steps, op)
		return f.fail
	})
}

func (f *fakeClusterCA) CAErrorKind(err error) string {
	if errors.Is(err, errFakeOwner) {
		return "rotation_owner"
	}
	return ""
}

func (f *fakeClusterCA) taken() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.steps...)
}

func clusterCAFixture(t *testing.T, cfg policy.Config) (*apiFixture, *fakeClusterCA) {
	t.Helper()
	fake := &fakeClusterCA{}
	f := newAPIFixture(t, true, withPolicy(cfg), func(c *Config) { c.ClusterCA = fake })
	f.api.argon = testArgon
	fake.pol = f.api.policy
	return f, fake
}

func TestClusterCAOutsideAP(t *testing.T) {
	f := newWebAdminFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	for _, r := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/cluster/ca", ""},
		{http.MethodPost, "/api/v1/cluster/ca/rotate", ""},
		{http.MethodPost, "/api/v1/cluster/tokens", `{}`},
	} {
		if resp := f.do(t, r.method, r.path, r.body, c); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %s = %d, want 404", r.method, r.path, resp.StatusCode)
		}
	}
}

// The web UI's rotation steps and join tokens need a session and the
// password entered again; a missing or expired re-authentication is refused
// and audited as a denial, and nothing happens.
func TestClusterCAReauth(t *testing.T) {
	f, fake := clusterCAFixture(t, policy.Config{})
	advance := fixtureClock(f)
	if resp := f.do(t, http.MethodPost, "/api/v1/cluster/ca/rotate", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("rotate without a session = %d, want 401", resp.StatusCode)
	}
	stale := staleSession(t, f)
	for _, r := range []struct {
		path, body string
		action     policy.Action
	}{
		{"/api/v1/cluster/ca/rotate", "", policy.ClusterCARotate},
		{"/api/v1/cluster/ca/finish", "", policy.ClusterCAFinish},
		{"/api/v1/cluster/ca/abort", "", policy.ClusterCAAbort},
		{"/api/v1/cluster/tokens", `{"ttl":"15m"}`, policy.ClusterTokenCreate},
	} {
		resp := f.do(t, http.MethodPost, r.path, r.body, stale)
		if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "reauth_required" {
			t.Fatalf("%s without re-auth = %d %s, want 403 reauth_required", r.path, resp.StatusCode, resp.body)
		}
		entries := auditOf(t, f, r.action)
		if len(entries) != 1 || entries[0].Decision != policy.Deny || entries[0].ActorKind != policy.ActorWeb ||
			!strings.Contains(entries[0].Result, "password was not entered again") {
			t.Fatalf("%s audit = %+v, want one re-auth denial", r.path, entries)
		}
	}
	if got := fake.taken(); len(got) != 0 {
		t.Fatalf("steps taken without re-auth: %q", got)
	}
	if n := countJoinTokens(t, f); n != 0 {
		t.Fatalf("%d join tokens created without re-auth", n)
	}

	// Signing in counts as entering it, for ReauthTTL.
	c := sessionCookie(t, f.login(t, testPassword))
	resp := f.do(t, http.MethodPost, "/api/v1/cluster/ca/rotate", "", c)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate = %d %s", resp.StatusCode, resp.body)
	}
	if st := decode[ClusterCAJSON](t, resp); st.Rotation == nil || st.Rotation.Stage != "started" {
		t.Fatalf("rotate answered %+v, want the status", st)
	}
	advance(ReauthTTL)
	if resp := f.do(t, http.MethodPost, "/api/v1/cluster/ca/finish", "", c); errorCode(t, resp) != "reauth_required" {
		t.Fatalf("finish after the re-auth expired = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/cluster/tokens", `{}`, c); errorCode(t, resp) != "reauth_required" {
		t.Fatalf("token after the re-auth expired = %d %s", resp.StatusCode, resp.body)
	}
	if got := fake.taken(); strings.Join(got, ",") != "rotate" {
		t.Fatalf("steps = %q, want rotate only", got)
	}
}

func countJoinTokens(t *testing.T, f *apiFixture) int {
	t.Helper()
	all, err := f.st.Audit().List(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range all {
		if e.Action == string(policy.ClusterTokenCreate) && e.Result == "ok" {
			n++
		}
	}
	return n
}

// Refusals and failures keep their meaning: the owner named, the members
// down, a denial by policy, an isolated master, an unknown step.
func TestClusterCARefusals(t *testing.T) {
	cases := []struct {
		name         string
		cfg          policy.Config
		refuse, fail error
		isolated     bool
		path         string
		status       int
		code, msg    string
	}{
		{name: "owner", refuse: errFakeOwner, path: "finish", status: http.StatusConflict, code: "rotation_owner", msg: "master hub-a"},
		{name: "members down", fail: errFakeDown, path: "finish", status: http.StatusBadGateway, code: "rotation_failed", msg: "hub-c"},
		{
			name: "policy", path: "rotate", status: http.StatusForbidden, code: "forbidden",
			cfg: policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeDeny}}},
		},
		{name: "isolated", isolated: true, path: "abort", status: http.StatusForbidden, code: "isolated"},
		{name: "unknown step", path: "explode", status: http.StatusNotFound, code: "not_found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, fake := clusterCAFixture(t, tc.cfg)
			fake.refuse, fake.fail = tc.refuse, tc.fail
			if tc.isolated {
				f.api.policy.FailClosedWhen(func() bool { return true })
			}
			c := sessionCookie(t, f.login(t, testPassword))
			resp := f.do(t, http.MethodPost, "/api/v1/cluster/ca/"+tc.path, "", c)
			if resp.StatusCode != tc.status || errorCode(t, resp) != tc.code || !strings.Contains(string(resp.body), tc.msg) {
				t.Fatalf("%s = %d %s, want %d %s with %q", tc.path, resp.StatusCode, resp.body, tc.status, tc.code, tc.msg)
			}
			if tc.refuse != nil {
				if got := fake.taken(); len(got) != 0 {
					t.Fatalf("a refused step ran: %q", got)
				}
				entries := auditOf(t, f, policy.ClusterCAFinish)
				if len(entries) != 1 || entries[0].Decision != policy.Deny || !strings.Contains(entries[0].Result, "master hub-a") {
					t.Fatalf("audit = %+v, want the refusal as a denial", entries)
				}
			}
		})
	}
}

// A join token is shown once, at creation, with the command that uses it,
// through this master: never logged, audited or stored but as a hash.
func TestClusterJoinToken(t *testing.T) {
	f, _ := clusterCAFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	for _, body := range []string{`{"ttl":"0s"}`, `{"ttl":"25h"}`, `{"ttl":"soon"}`, `{"allow_roles":["node"]}`, `{"extra":1}`} {
		if resp := f.do(t, http.MethodPost, "/api/v1/cluster/tokens", body, c); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("create %s = %d, want 400", body, resp.StatusCode)
		}
	}
	for _, tc := range []struct {
		body, flag string
	}{
		{`{"ttl":"1h"}`, ""},
		{`{"allow_roles":["storage","master"]}`, ""},
		{`{"allow_roles":["storage"]}`, " --allow-roles storage"},
		{`{"allow_roles":["master"]}`, " --allow-roles master"},
	} {
		resp := f.do(t, http.MethodPost, "/api/v1/cluster/tokens", tc.body, c)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s = %d %s", tc.body, resp.StatusCode, resp.body)
		}
		got := decode[ClusterTokenJSON](t, resp)
		tok, err := pki.ParseJoinToken(got.Token)
		if err != nil {
			t.Fatalf("token %q: %v", got.Token, err)
		}
		if tok.CAFingerprint != pki.Fingerprint(f.api.ca.Cert()) {
			t.Error("the token does not pin this hub's CA")
		}
		want := "HEARTH_JOIN_TOKEN=" + got.Token + " hearth hub --join " + got.HubURL + tc.flag
		if got.JoinCommand != want || !strings.HasPrefix(got.HubURL, "https://") || !strings.HasSuffix(got.HubURL, ":"+DefaultAgentPort) {
			t.Fatalf("join command %q, want %q", got.JoinCommand, want)
		}
		for _, where := range []string{f.logs.String(), allAuditText(t, f)} {
			if strings.Contains(where, tok.Secret) || strings.Contains(where, got.Token) {
				t.Fatal("the token secret is in the logs or the audit log")
			}
		}
		// Single use, stored by its hash.
		if err := f.st.JoinTokens().Consume(t.Context(), tok.Secret, time.Now()); err != nil {
			t.Fatalf("consume: %v", err)
		}
		if err := f.st.JoinTokens().Consume(t.Context(), tok.Secret, time.Now()); !errors.Is(err, store.ErrTokenUsed) {
			t.Fatalf("second consume: %v, want ErrTokenUsed", err)
		}
	}
	entries := auditOf(t, f, policy.ClusterTokenCreate)
	if len(entries) == 0 || entries[0].ActorKind != policy.ActorWeb || !strings.Contains(string(entries[0].Detail), `"ttl"`) {
		t.Fatalf("audit = %+v, want the creations by web with their TTL", entries)
	}

	// Denied by policy: no token.
	g, _ := clusterCAFixture(t, policy.Config{
		Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeDeny}},
	})
	gc := sessionCookie(t, g.login(t, testPassword))
	if resp := g.do(t, http.MethodPost, "/api/v1/cluster/tokens", `{}`, gc); resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "forbidden" {
		t.Fatalf("create denied by policy = %d %s, want 403 forbidden", resp.StatusCode, resp.body)
	}
	if n := countJoinTokens(t, g); n != 0 {
		t.Fatalf("%d tokens created against the policy", n)
	}
}

// allAuditText is every audit entry of f, as text.
func allAuditText(t *testing.T, f *apiFixture) string {
	t.Helper()
	all, err := f.st.Audit().List(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range all {
		fmt.Fprintf(&b, "%s %s %s %s %s\n", e.ActorID, e.Target, e.Result, e.Detail, e.Action)
	}
	return b.String()
}
