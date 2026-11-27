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

// TestConcurrentResets: two masters reset the password at once; whichever
// password wins, the session epoch is the higher of the two on both, so the
// sessions of neither reset's epoch-before survive.
func TestConcurrentResets(t *testing.T) {
	ctx := t.Context()
	a, b := openTest(t), openTest(t)
	now := time.Now()
	h := hashSecret("old")
	created := applyOn(t, a, CreateSession{Stamp: stampAt(now, "a"), Hash: h[:], Now: toMillis(now), ExpiresAt: toMillis(now.Add(time.Hour))})
	if err := b.Merge(ctx, created); err != nil {
		t.Fatal(err)
	}
	// a's reset has the higher epoch, b's the newer stamp: b's password
	// wins, a's epoch stays.
	ra := applyOn(t, a, SetPasswordHash{Stamp: stampAt(now.Add(time.Second), "a"), Hash: "pa", Now: toMillis(now.Add(time.Hour))})
	rb := applyOn(t, b, SetPasswordHash{Stamp: stampAt(now.Add(2*time.Second), "b"), Hash: "pb", Now: toMillis(now)})
	if err := a.Merge(ctx, rb); err != nil {
		t.Fatal(err)
	}
	if err := b.Merge(ctx, ra); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]*Store{"a": a, "b": b} {
		var hash string
		var epoch int64
		if err := s.db.QueryRowContext(ctx, `SELECT password_hash, session_epoch FROM admin WHERE id = 1`).Scan(&hash, &epoch); err != nil {
			t.Fatal(err)
		}
		if hash != "pb" || epoch != toMillis(now.Add(time.Hour)) {
			t.Errorf("%s: password %q, epoch %d; want pb, %d", name, hash, epoch, toMillis(now.Add(time.Hour)))
		}
		if _, err := s.Admin().CheckSession(ctx, "old", now); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: the session from before both resets: %v, want not found", name, err)
		}
	}
}

// TestSessionTombstoneWins: a sign-out wins over the session it ends, even
// when the master that created it stamped it later than the tombstone (its
// clock ahead): the deletion is final both ways, and the side that holds
// the tombstone stamps it past the session, so anti-entropy carries it.
func TestSessionTombstoneWins(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	h := hashSecret("s")
	t.Run("tombstone reaches the session", func(t *testing.T) {
		a, b := openTest(t), openTest(t)
		created := applyOn(t, a, CreateSession{Stamp: stampAt(now.Add(time.Minute), "a"), Hash: h[:], Now: toMillis(now), ExpiresAt: toMillis(now.Add(time.Hour))})
		tomb := applyOn(t, b, DeleteSession{Stamp: stampAt(now, "b"), Hash: h[:], At: toMillis(now.Add(time.Second))})
		if err := a.Merge(ctx, tomb); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Admin().CheckSession(ctx, "s", now); !errors.Is(err, ErrNotFound) {
			t.Fatalf("session after an older-stamped sign-out: %v, want not found", err)
		}
		got, err := a.ReadRows(ctx, []RowRef{{Table: "sessions", Key: Values{h[:]}}})
		if err != nil || len(got) != 1 || !got[0].Deleted || got[0].HLC <= created[0].HLC {
			t.Fatalf("a's row: %+v, %v; want a tombstone stamped past the session", got, err)
		}
	})
	t.Run("session reaches the tombstone", func(t *testing.T) {
		a, b := openTest(t), openTest(t)
		created := applyOn(t, a, CreateSession{Stamp: stampAt(now.Add(time.Minute), "a"), Hash: h[:], Now: toMillis(now), ExpiresAt: toMillis(now.Add(time.Hour))})
		applyOn(t, b, DeleteSession{Stamp: stampAt(now, "b"), Hash: h[:], At: toMillis(now.Add(time.Second))})
		if err := b.Merge(ctx, created); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Admin().CheckSession(ctx, "s", now); !errors.Is(err, ErrNotFound) {
			t.Fatalf("session after its row came late, stamped later: %v, want not found", err)
		}
		got, err := b.ReadRows(ctx, []RowRef{{Table: "sessions", Key: Values{h[:]}}})
		if err != nil || len(got) != 1 || !got[0].Deleted || got[0].HLC <= created[0].HLC {
			t.Fatalf("b's row: %+v, %v; want a tombstone stamped past the session", got, err)
		}
	})
	t.Run("a session created after the sign-out", func(t *testing.T) {
		// Not one a sign-out could have meant: its row wins as usual.
		a, b := openTest(t), openTest(t)
		applyOn(t, b, DeleteSession{Stamp: stampAt(now, "b"), Hash: h[:], At: toMillis(now)})
		created := applyOn(t, a, CreateSession{Stamp: stampAt(now.Add(time.Minute), "a"), Hash: h[:], Now: toMillis(now.Add(time.Second)), ExpiresAt: toMillis(now.Add(time.Hour))})
		if err := b.Merge(ctx, created); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Admin().CheckSession(ctx, "s", now); err != nil {
			t.Fatalf("session created after the tombstone: %v", err)
		}
	})
}
