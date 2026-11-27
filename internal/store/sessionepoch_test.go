// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/hlc"
)

// Two masters' copies of the sessions (#384): a reset on one ends, on the
// other, the sessions it never held, and a sign-out of a session one does
// not hold still ends it on the other.

// stampAt stamps a command of origin at wall time at.
func stampAt(at time.Time, origin string) Stamp { return Stamp{HLC: hlc.New(at), Origin: origin} }

// applyOn applies cmd on s and returns the rows it wrote.
func applyOn(t *testing.T, s *Store, cmd Command) []Mutation {
	t.Helper()
	_, muts, err := s.ApplyLocalMutations(t.Context(), cmd)
	if err != nil {
		t.Fatalf("%s: %v", cmd.Op(), err)
	}
	return muts
}

func TestPasswordResetEndsSessionsByEpoch(t *testing.T) {
	ctx := t.Context()
	a, b := openTest(t), openTest(t)
	now := time.Now()
	h := hashSecret("on-b")
	// b signs in under the old password, then a reset on a reaches it.
	if err := b.Merge(ctx, applyOn(t, a, SetPasswordHash{Hash: "old", Now: toMillis(now)})); err != nil {
		t.Fatal(err)
	}
	applyOn(t, b, CreateSession{Hash: h[:], Now: toMillis(now), ExpiresAt: toMillis(now.Add(time.Hour))})
	if _, err := b.Admin().CheckSession(ctx, "on-b", now); err != nil {
		t.Fatalf("session before the reset: %v", err)
	}
	// a's clock is behind b's: the epoch still rises past the one before.
	reset := applyOn(t, a, SetPasswordHash{Hash: "new", Now: toMillis(now.Add(-time.Hour))})
	if err := b.Merge(ctx, reset); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Admin().CheckSession(ctx, "on-b", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session from before the reset: %v, want not found", err)
	}
	// A session b creates after it took the reset is valid, whatever the
	// clocks say.
	h2 := hashSecret("after")
	applyOn(t, b, CreateSession{Hash: h2[:], Now: toMillis(now.Add(-2 * time.Hour)), ExpiresAt: toMillis(now.Add(time.Hour))})
	if _, err := b.Admin().CheckSession(ctx, "after", now); err != nil {
		t.Fatalf("session after the reset: %v", err)
	}
}

func TestSignOutOfASessionNotHeld(t *testing.T) {
	ctx := t.Context()
	a, b := openTest(t), openTest(t)
	now := time.Now()
	h := hashSecret("on-a")
	created := applyOn(t, a, CreateSession{Stamp: stampAt(now, "a"), Hash: h[:], Now: toMillis(now), ExpiresAt: toMillis(now.Add(time.Hour))})
	// b never got it, and signs it out.
	tomb := applyOn(t, b, DeleteSession{Stamp: stampAt(now.Add(time.Second), "b"), Hash: h[:]})
	if len(tomb) != 1 || !tomb[0].Deleted {
		t.Fatalf("sign-out of a session b does not hold wrote %v, want a tombstone", tomb)
	}
	if err := a.Merge(ctx, tomb); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Admin().CheckSession(ctx, "on-a", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session after the sign-out on b: %v, want not found", err)
	}
	// The session's own row, late, does not revive it.
	if err := b.Merge(ctx, created); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Admin().CheckSession(ctx, "on-a", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session on b after its row came late: %v, want not found", err)
	}
	// Signing out again writes nothing more.
	if again := applyOn(t, b, DeleteSession{Stamp: stampAt(now.Add(2*time.Second), "b"), Hash: h[:]}); len(again) != 0 {
		t.Fatalf("a second sign-out wrote %v", again)
	}
}
