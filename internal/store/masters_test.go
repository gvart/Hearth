// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"testing"
	"time"
)

// TestOwnedRowsRefuseOtherMasters: a token or approval owned by master a is
// refused, naming a, when master b consumes or decides it; a may, and so may
// a single hub (no master); any master may expire an approval.
func TestOwnedRowsRefuseOtherMasters(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	now := time.Now()
	h := hashSecret("secret")
	if _, err := s.apply(ctx, CreateToken{Hash: h[:], Labels: "{}", ExpiresAt: toMillis(now.Add(time.Hour)), Owner: "a"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.apply(ctx, ConsumeToken{Hash: h[:], Now: toMillis(now), Master: "b"})
	if !errors.Is(err, ErrNotOwner) || OwnerOf(err) != "a" {
		t.Fatalf("consume on b = %v, want ErrNotOwner naming a", err)
	}
	if _, err := s.apply(ctx, ConsumeToken{Hash: h[:], Now: toMillis(now), Master: "a"}); err != nil {
		t.Fatalf("consume on a = %v", err)
	}
	if _, err := s.apply(ctx, ConsumeToken{Hash: h[:], Now: toMillis(now), Master: "a"}); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("second consume on a = %v, want ErrTokenUsed", err)
	}

	for _, id := range []string{"ap-1", "ap-2"} {
		if _, err := s.apply(ctx, CreateApproval{
			ID: id, CreatedAt: toMillis(now), ExpiresAt: toMillis(now.Add(time.Hour)), ActorKind: "web", ActorID: "x",
			Action: "device.exec", Class: "dangerous", Target: "dev-1", Detail: "{}", Owner: "a",
		}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = s.apply(ctx, DecideApproval{ID: "ap-1", Status: ApprovalApproved, By: "web:x", At: toMillis(now), Master: "b"})
	if !errors.Is(err, ErrNotOwner) || OwnerOf(err) != "a" {
		t.Fatalf("approve on b = %v, want ErrNotOwner naming a", err)
	}
	if _, err := s.apply(ctx, DecideApproval{ID: "ap-1", Status: ApprovalDenied, By: "web:x", At: toMillis(now), Master: "a"}); err != nil {
		t.Fatalf("deny on a = %v", err)
	}
	if _, err := s.apply(ctx, DecideApproval{ID: "ap-2", Status: ApprovalExpired, By: "sweep", At: toMillis(now), Master: "b"}); err != nil {
		t.Fatalf("expire on b = %v", err)
	}
}
