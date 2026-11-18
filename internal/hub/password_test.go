// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"errors"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// testArgon keeps tests fast; production parameters are checked once.
var testArgon = argonParams{time: 1, memory: 64, threads: 1}

// legacyHash is "correct horse" hashed with four lanes (p=4), as hubs did
// before #94, at cheap cost parameters.
const legacyHash = "$argon2id$v=19$m=64,t=1,p=4$Av/SlOxmdhlu2fxmB66uOw$06vENb3YO5W8xIMBpq3Vm032ngp1Z5P8/pof6D9s81g"

func TestHashPassword(t *testing.T) {
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") || strings.Contains(h, "correct horse") {
		t.Fatalf("hash = %q", h)
	}
	if ok, err := verifyPassword(h, "correct horse"); err != nil || !ok {
		t.Fatalf("default hash does not verify: %v %v", ok, err)
	}
	// One lane, so hashing cannot crowd Raft off a single-core hub (#94), at no
	// less than OWASP's argon2id minimum (m=19 MiB, t=2).
	if !strings.Contains(h, "$m=65536,t=3,p=1$") {
		t.Fatalf("default parameters changed: %q", h)
	}

	// The rest uses cheap parameters: the race detector makes argon2 slow.
	h, err = hashPassword("correct horse", testArgon)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := hashPassword("correct horse", testArgon)
	if err != nil {
		t.Fatal(err)
	}
	if h == h2 {
		t.Error("two hashes of one password are equal: salt not random")
	}

	tests := []struct {
		name    string
		hash    string
		pw      string
		want    bool
		wantErr bool
	}{
		{"right password", h, "correct horse", true, false},
		// Hashes from before #94 have four lanes; verification uses the
		// parameters in the hash, so they keep working.
		{"four-lane hash", legacyHash, "correct horse", true, false},
		{"four-lane hash, wrong password", legacyHash, "correct horsf", false, false},
		{"wrong password", h, "correct horsf", false, false},
		{"empty password", h, "", false, false},
		{"not a PHC string", "plain", "correct horse", false, true},
		{"other algorithm", strings.Replace(h, "argon2id", "argon2i", 1), "correct horse", false, true},
		{"bad version", strings.Replace(h, "v=19", "v=16", 1), "correct horse", false, true},
		{"bad params", strings.Replace(h, "m=", "x=", 1), "correct horse", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verifyPassword(tt.hash, tt.pw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetAdminPassword(t *testing.T) {
	ctx := t.Context()
	st := newTestStore(t)
	pol := policy.New(st.Audit())

	if err := setAdminPassword(ctx, st, pol, "root", "short", testArgon); err == nil {
		t.Fatal("short password accepted")
	}
	if _, err := st.Admin().PasswordHash(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("short password stored: %v", err)
	}
	if err := setAdminPassword(ctx, st, pol, "root", "long enough", testArgon); err != nil {
		t.Fatal(err)
	}
	h, err := st.Admin().PasswordHash(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := verifyPassword(h, "long enough"); err != nil || !ok {
		t.Fatalf("stored hash does not verify: %v %v", ok, err)
	}
	entries, err := st.Audit().List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != string(policy.AdminSetPassword) || entries[0].Decision != policy.Allow {
		t.Fatalf("audit = %+v, want one allowed admin.set_password", entries)
	}
	if strings.Contains(string(entries[0].Detail)+entries[0].Result, "long enough") {
		t.Fatal("password in audit log")
	}
}
