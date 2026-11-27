// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// `hearth token list` shows the unused tokens by ID, and `hearth token
// revoke` spends one so it cannot enroll; a used or unknown one is refused.
// Each revocation is a token.revoke decision by admin, refusals too.
func TestTokenListRevoke(t *testing.T) {
	dir, _ := initHub(t)
	st := openStore(t, dir)
	id := func(secret string) string {
		h := sha256.Sum256([]byte(secret))
		return hex.EncodeToString(h[:6])
	}
	exp := time.Now().Add(time.Hour)
	if err := st.Tokens().CreateHub(t.Context(), "hub-secret", "garage", "storage,master", map[string]string{"room": "attic"}, exp); err != nil {
		t.Fatal(err)
	}
	if err := st.Tokens().Create(t.Context(), "plain-secret", nil, exp); err != nil {
		t.Fatal(err)
	}

	out, err := execute(t, "token", "list", "--data-dir", dir)
	if err != nil {
		t.Fatalf("token list: %v\n%s", err, out)
	}
	for _, want := range []string{id("hub-secret"), "garage", "yes", "room=attic", id("plain-secret")} {
		if !strings.Contains(out, want) {
			t.Errorf("token list lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "secret") {
		t.Errorf("token list shows a secret:\n%s", out)
	}

	if out, err := execute(t, "token", "revoke", "--data-dir", dir, id("hub-secret")); err != nil || !strings.Contains(out, "Revoked") {
		t.Fatalf("token revoke: %v\n%s", err, out)
	}
	if _, err := st.Tokens().Consume(t.Context(), "hub-secret", time.Now()); !errors.Is(err, store.ErrTokenUsed) {
		t.Fatalf("enroll with a revoked token = %v, want it refused", err)
	}
	if _, err := execute(t, "token", "revoke", "--data-dir", dir, id("hub-secret")); err == nil || !strings.Contains(err.Error(), "used or revoked") {
		t.Fatalf("revoke again = %v, want refused", err)
	}
	if _, err := execute(t, "token", "revoke", "--data-dir", dir, "0123456789ab"); err == nil || !strings.Contains(err.Error(), "no enrollment token") {
		t.Fatalf("revoke unknown = %v, want refused", err)
	}
	if out, err := execute(t, "token", "list", "--data-dir", dir); err != nil || strings.Contains(out, id("hub-secret")) {
		t.Fatalf("token list after revoke: %v\n%s", err, out)
	}

	entries, err := st.Audit().List(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.Action == string(policy.TokenRevoke) && e.ActorKind == policy.ActorAdmin {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("audit = %+v, want three token.revoke entries by admin", entries)
	}
}
