// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/mcpserver"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func TestMCPTokenCommands(t *testing.T) {
	dir, _ := initHub(t)
	out, err := execute(t, "mcp", "token", "create", "claude", "--data-dir", dir)
	if err != nil {
		t.Fatalf("create = %v\n%s", err, out)
	}
	secret := regexp.MustCompile(mcpserver.TokenPrefix + `[a-z0-9]+`).FindString(out)
	if secret == "" || !strings.Contains(out, "scope safe") {
		t.Fatalf("create printed no token:\n%s", out)
	}
	st := openStore(t, dir)
	tok, err := st.MCPTokens().Check(t.Context(), secret)
	if err != nil || tok.Name != "claude" || tok.Scope != "safe" {
		t.Fatalf("Check = %+v, %v", tok, err)
	}
	if out, err := execute(t, "mcp", "token", "create", "claude", "--data-dir", dir); err == nil {
		t.Errorf("a name was reused:\n%s", out)
	}
	for _, args := range [][]string{{"Bad Name"}, {"x", "--scope", "admin"}} {
		if _, err := execute(t, append([]string{"mcp", "token", "create", "--data-dir", dir}, args...)...); err == nil {
			t.Errorf("create %v succeeded", args)
		}
	}
	if out, err := execute(t, "mcp", "token", "create", "dry", "--dry-run", "--data-dir", dir); err != nil || !strings.Contains(out, "Dry run") {
		t.Errorf("dry run = %v\n%s", err, out)
	}
	if out, err := execute(t, "mcp", "token", "revoke", "claude", "--data-dir", dir); err != nil || !strings.Contains(out, "Revoked") {
		t.Fatalf("revoke = %v\n%s", err, out)
	}
	if _, err := st.MCPTokens().Check(t.Context(), secret); !errors.Is(err, store.ErrTokenRevoked) {
		t.Errorf("Check after revoke = %v", err)
	}
	if _, err := execute(t, "mcp", "token", "revoke", "claude", "--data-dir", dir); err == nil {
		t.Error("revoking twice succeeded")
	}
	out, err = execute(t, "mcp", "token", "list", "--data-dir", dir)
	if err != nil || !strings.Contains(out, "claude") || strings.Contains(out, "dry") || strings.Contains(out, secret) {
		t.Errorf("list = %v\n%s", err, out)
	}
	audit, err := st.Audit().List(t.Context(), 20)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range audit {
		if strings.Contains(string(e.Detail), secret) || strings.Contains(e.Result, secret) {
			t.Fatal("the token secret is in the audit log")
		}
		actions = append(actions, e.Action)
	}
	if !strings.Contains(strings.Join(actions, " "), string(policy.MCPTokenCreate)) ||
		!strings.Contains(strings.Join(actions, " "), string(policy.MCPTokenRevoke)) {
		t.Errorf("audit actions = %v", actions)
	}
}

func TestMCPNeedsToken(t *testing.T) {
	t.Setenv("HEARTH_MCP_TOKEN", "")
	if _, err := execute(t, "mcp"); err == nil || !strings.Contains(err.Error(), "HEARTH_MCP_TOKEN") {
		t.Errorf("mcp without a token = %v", err)
	}
	for raw, want := range map[string]string{
		"http://hub.lan:7080":   "http://hub.lan:7080/mcp",
		"https://hub.lan:7443/": "https://hub.lan:7443/mcp",
	} {
		if got, err := mcpEndpoint(raw); err != nil || got != want {
			t.Errorf("mcpEndpoint(%s) = %s, %v", raw, got, err)
		}
	}
	if _, err := mcpEndpoint("hub.lan"); err == nil {
		t.Error("mcpEndpoint accepted a URL without a scheme")
	}
}
