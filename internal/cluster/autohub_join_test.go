// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
)

// A join token minted for a device at its enrollment (#328) has the caps
// checked again where the CA key leaves: past 3 masters the device joins as
// storage only and gets no CA key; past 5 storage members it is refused.
// The join response names the master's gossip address, which the joiner
// keeps as a seed (#334). A token joins once, and not after it expired.
func TestJoinMintedTokenCaps(t *testing.T) {
	ctx := t.Context()
	an := newAPNet(t, 1, "a")
	m := an.m("a")
	ca := newTestCA(t)
	node := &APNode{cfg: APConfig{NodeID: "a", Advertise: "192.0.2.10:7444"}, rep: m.rep, st: m.st, log: testLogger(t)}
	js := NewAPJoinServer(node, m.st, ca, policy.New(m.st.Audit()), testLogger(t))
	var masters, storage int
	js.hubCounts = func(string) (int, int) { return masters, storage }
	cert, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, h := js.Handler()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	schema, err := m.st.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mint := func(t *testing.T, device string, expires time.Time) string {
		t.Helper()
		tok, err := pki.NewToken(ca.Cert())
		if err != nil {
			t.Fatal(err)
		}
		if err := m.st.JoinTokens().CreateFor(ctx, tok.Secret, expires, HubRoles.String(), device); err != nil {
			t.Fatal(err)
		}
		return tok.EncodeJoin()
	}
	join := func(dir, token string, i int) error {
		return Join(ctx, JoinParams{
			URL: srv.URL, Token: token, DataDir: dir, NodeID: fmt.Sprintf("dev-%d", i),
			Address: "192.0.2.20:7444", MaxSchema: schema, AllowedRoles: HubRoles,
		})
	}

	for i, tc := range []struct {
		name             string
		device           string
		masters, storage int
		want             RoleSet
		refused          string
	}{
		{"room for a master", "d1", 2, 2, HubRoles, ""},
		{"3 masters", "d2", 3, 3, RolesOf(RoleStorage), ""},
		{"admin token ignores the caps", "", 3, 5, HubRoles, ""},
		{"5 storage members", "d3", 1, 5, 0, "storage members already"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			masters, storage = tc.masters, tc.storage
			dir := t.TempDir()
			err := join(dir, mint(t, tc.device, time.Now().Add(time.Hour)), i)
			if tc.refused != "" {
				if err == nil || !strings.Contains(err.Error(), tc.refused) {
					t.Fatalf("join = %v, want refused with %q", err, tc.refused)
				}
				if _, err := os.Stat(filepath.Join(dir, pki.CAKeyFile)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("a refused join wrote the CA key: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			lr, err := LoadLocalRoles(dir, HubRoles, nil)
			if err != nil || lr.Roles != tc.want {
				t.Fatalf("roles = %s, %v; want %s", lr.Roles, err, tc.want)
			}
			_, keyErr := os.Stat(filepath.Join(dir, pki.CAKeyFile))
			if (keyErr == nil) != tc.want.Has(RoleMaster) {
				t.Fatalf("CA key written = %v, want %v", keyErr == nil, tc.want.Has(RoleMaster))
			}
			seeds, err := os.ReadFile(filepath.Join(dir, StateDir, seedsFile))
			if err != nil || strings.TrimSpace(string(seeds)) != "192.0.2.10:7444" {
				t.Fatalf("seeds = %q, %v; want the master's gossip address", seeds, err)
			}
		})
	}

	entries, err := m.st.Audit().List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var capped int
	for _, e := range entries {
		if e.Action == string(policy.ClusterJoin) && strings.Contains(string(e.Detail), `"capped":true`) {
			capped++
		}
	}
	if capped != 2 {
		t.Fatalf("%d capped joins in the audit log, want 2", capped)
	}

	t.Run("reused, expired, unknown", func(t *testing.T) {
		masters, storage = 0, 0
		tok := mint(t, "d4", time.Now().Add(time.Hour))
		if err := join(t.TempDir(), tok, 10); err != nil {
			t.Fatal(err)
		}
		if err := join(t.TempDir(), tok, 11); err == nil || !strings.Contains(err.Error(), "already used") {
			t.Fatalf("reused = %v", err)
		}
		if err := join(t.TempDir(), mint(t, "d5", time.Now().Add(-time.Minute)), 12); err == nil ||
			!strings.Contains(err.Error(), "expired") {
			t.Fatalf("expired = %v", err)
		}
		other, _ := pki.NewToken(ca.Cert())
		if err := join(t.TempDir(), other.EncodeJoin(), 13); err == nil || !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("unknown = %v", err)
		}
	})
}

