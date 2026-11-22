// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

var errLastMaster = errors.New("the last master cannot be demoted or removed")

// fakeClusterAdmin records the role changes it is asked for.
type fakeClusterAdmin struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakeClusterAdmin) Status(context.Context) any {
	return map[string]any{"node_id": "a", "members": []any{}}
}

func (f *fakeClusterAdmin) record(op, member, role string) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, op+" "+member+" "+role)
	if f.err != nil {
		return nil, f.err
	}
	return map[string]string{"member": member, "role": role, "state": "done"}, nil
}

func (f *fakeClusterAdmin) Promote(_ context.Context, member, role string) (any, error) {
	return f.record("promote", member, role)
}

func (f *fakeClusterAdmin) Demote(_ context.Context, member, role string) (any, error) {
	return f.record("demote", member, role)
}

func (f *fakeClusterAdmin) Remove(_ context.Context, member string) (any, error) {
	return f.record("remove", member, "")
}

func (f *fakeClusterAdmin) ErrorKind(err error) string {
	if errors.Is(err, errLastMaster) {
		return "last_master"
	}
	return ""
}

func (f *fakeClusterAdmin) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func clusterFixture(t *testing.T, admin ClusterAdmin) (*apiFixture, *http.Cookie) {
	t.Helper()
	f := newAPIFixture(t, true, func(c *Config) {
		if admin != nil {
			c.ClusterAdmin = admin
		}
	})
	if err := f.st.Admin().CreateSession(t.Context(), "cluster-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return f, testCookie("cluster-session")
}

// clusterAudit returns the audit entries of the role changes.
func clusterAudit(t *testing.T, f *apiFixture) []string {
	t.Helper()
	all, err := f.st.Audit().List(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range all {
		if strings.HasPrefix(e.Action, "cluster.") {
			out = append(out, e.Action+" "+e.Target+" "+e.Decision)
		}
	}
	return out
}

func TestClusterMembersOutsideAP(t *testing.T) {
	f, cookie := clusterFixture(t, nil)
	for _, r := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/cluster/members", ""},
		{http.MethodPost, "/api/v1/cluster/members/b/promote", `{"role": "storage"}`},
		{http.MethodDelete, "/api/v1/cluster/members/b", ""},
	} {
		if resp := f.do(t, r.method, r.path, r.body, cookie); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %s = %d, want 404", r.method, r.path, resp.StatusCode)
		}
	}
}

func TestClusterRoleChanges(t *testing.T) {
	admin := &fakeClusterAdmin{}
	f, cookie := clusterFixture(t, admin)
	if resp := f.do(t, http.MethodGet, "/api/v1/cluster/members", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("members without a session = %d, want 401", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodGet, "/api/v1/cluster/members", "", cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("members = %d %s", resp.StatusCode, resp.body)
	}
	for _, r := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/cluster/members/b/promote", `{"role": "master"}`},
		{http.MethodPost, "/api/v1/cluster/members/b/demote", `{"role": "storage"}`},
		{http.MethodDelete, "/api/v1/cluster/members/c", ""},
	} {
		if resp := f.do(t, r.method, r.path, r.body, cookie); resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s = %d %s", r.method, r.path, resp.StatusCode, resp.body)
		}
	}
	want := []string{"promote b master", "demote b storage", "remove c "}
	if got := admin.called(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	audit := strings.Join(clusterAudit(t, f), "|")
	for _, w := range []string{"cluster.promote b allow", "cluster.demote b allow", "cluster.remove c allow"} {
		if !strings.Contains(audit, w) {
			t.Fatalf("audit %q lacks %q", audit, w)
		}
	}
}

func TestClusterRoleChangeRefusals(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(f *apiFixture, admin *fakeClusterAdmin)
		path   string
		body   string
		status int
		code   string
		ran    bool
	}{
		{
			name:   "bad role",
			path:   "/api/v1/cluster/members/b/promote",
			body:   `{"role": "node"}`,
			status: http.StatusBadRequest, code: "bad_request",
		},
		{
			name:   "bad member",
			path:   "/api/v1/cluster/members/b%20c/promote",
			body:   `{"role": "storage"}`,
			status: http.StatusBadRequest, code: "bad_request",
		},
		{
			name: "denied by policy",
			setup: func(f *apiFixture, _ *fakeClusterAdmin) {
				f.api.policy.SetConfig(policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeDeny}})
			},
			path:   "/api/v1/cluster/members/b/promote",
			body:   `{"role": "storage"}`,
			status: http.StatusForbidden, code: "forbidden",
		},
		{
			name:   "isolated master",
			setup:  func(f *apiFixture, _ *fakeClusterAdmin) { f.api.policy.FailClosedWhen(func() bool { return true }) },
			path:   "/api/v1/cluster/members/b/demote",
			body:   `{"role": "master"}`,
			status: http.StatusForbidden, code: "isolated",
		},
		{
			name:   "last master",
			setup:  func(_ *apiFixture, admin *fakeClusterAdmin) { admin.err = errLastMaster },
			path:   "/api/v1/cluster/members/b/demote",
			body:   `{"role": "master"}`,
			status: http.StatusConflict, code: "last_master", ran: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			admin := &fakeClusterAdmin{}
			f, cookie := clusterFixture(t, admin)
			if tc.setup != nil {
				tc.setup(f, admin)
			}
			resp := f.do(t, http.MethodPost, tc.path, tc.body, cookie)
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d %s, want %d", resp.StatusCode, resp.body, tc.status)
			}
			if got := decode[ErrorJSON](t, resp); got.Code != tc.code {
				t.Fatalf("code = %q (%s), want %q", got.Code, got.Error, tc.code)
			}
			if ran := len(admin.called()) > 0; ran != tc.ran {
				t.Fatalf("ran = %v, want %v", ran, tc.ran)
			}
			audit := clusterAudit(t, f)
			if tc.code == "bad_request" && len(audit) != 0 {
				t.Fatalf("a malformed change was audited: %q", audit)
			}
			if tc.code == "forbidden" || tc.code == "isolated" {
				if len(audit) == 0 || !strings.HasSuffix(audit[len(audit)-1], "deny") {
					t.Fatalf("audit = %q, want the denial", audit)
				}
			}
		})
	}
}
