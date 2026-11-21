// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"crypto/tls"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
)

// TestJoinTakesGrantedRoles: a hub joining with a join token starts with the
// roles the token and its --allow-roles both allow, and writes the CA key
// only when granted master, whatever its host allows.
func TestJoinTakesGrantedRoles(t *testing.T) {
	ctx := t.Context()
	an := newAPNet(t, 1, "a")
	m := an.m("a")
	ca := newTestCA(t)
	node := &APNode{cfg: APConfig{NodeID: "a"}, rep: m.rep, st: m.st, log: testLogger(t)}
	js := NewAPJoinServer(node, m.st, ca, policy.New(m.st.Audit()), testLogger(t))
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

	for i, tc := range []struct {
		name           string
		token, allowed RoleSet
		want           RoleSet
	}{
		{"storage token, host allows master", RolesOf(RoleStorage), HubRoles, RolesOf(RoleStorage)},
		{"master token, storage-only host", HubRoles, RolesOf(RoleStorage), RolesOf(RoleStorage)},
		{"master token, master host", HubRoles, HubRoles, HubRoles},
		{"storage token, master-only host", RolesOf(RoleStorage), RolesOf(RoleMaster), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := pki.NewToken(ca.Cert())
			if err != nil {
				t.Fatal(err)
			}
			if err := m.st.JoinTokens().Create(ctx, tok.Secret, time.Now().Add(time.Hour), tc.token.String()); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			err = Join(ctx, JoinParams{
				URL: srv.URL, Token: tok.EncodeJoin(), DataDir: dir, NodeID: fmt.Sprintf("hub-%d", i),
				Address: "127.0.0.1:7946", MaxSchema: schema, AllowedRoles: tc.allowed,
			})
			if tc.want == 0 {
				if err == nil {
					t.Fatal("joined with no role granted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			lr, err := LoadLocalRoles(dir, tc.allowed, nil)
			if err != nil || lr.Roles != tc.want {
				t.Fatalf("roles after join = %s, %v; want %s", lr.Roles, err, tc.want)
			}
			_, keyErr := os.Stat(filepath.Join(dir, pki.CAKeyFile))
			if hasKey := keyErr == nil; hasKey != tc.want.Has(RoleMaster) {
				t.Fatalf("CA key written = %v (%v), want %v", hasKey, keyErr, tc.want.Has(RoleMaster))
			}
			if _, err := os.Stat(filepath.Join(dir, pki.CACertFile)); err != nil {
				t.Fatalf("CA certificate: %v", err)
			}
		})
	}
}
