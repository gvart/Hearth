// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"testing"
	"time"
)

// replicaSet is member a of a sharded cluster reading a partition whose
// first replica asked, first, has no row of it (it missed the write: hinted
// to it while it was down), while x has the newest version and y may have
// an older one.
type replicaSet struct {
	a, first, x, y *Store
}

// newReplicaSet returns a replica set where a holds the partition (holder
// "a": a's own copy is read first) or does not (holder "b": b is read
// first).
func newReplicaSet(t *testing.T, holder string) replicaSet {
	t.Helper()
	sh := &fakeShards{self: "a", key: func(string) string { return holder }, replicas: []string{"a", "b", "c"}}
	a := openTestWith(t, WithShards(sh), WithOrigin("a"))
	b := openTestWith(t, WithDigest(), WithOrigin("b"))
	c := openTestWith(t, WithDigest(), WithOrigin("c"))
	sh.members = map[string]*Store{"a": a, "b": b, "c": c}
	if holder == "a" {
		return replicaSet{a: a, first: a, x: b, y: c}
	}
	return replicaSet{a: a, first: b, x: c, y: a}
}

func (rs replicaSet) apply(t *testing.T, s *Store, cmd Command) {
	t.Helper()
	if _, err := s.ApplyLocal(t.Context(), withStamp(cmd, Stamp{HLC: rs.a.clock.Now(), Origin: s.origin})); err != nil {
		t.Fatalf("%s on %s: %v", cmd.Op(), s.origin, err)
	}
}

func copyRows(t *testing.T, from, to *Store, refs []RowRef) {
	t.Helper()
	muts, err := from.ReadRows(t.Context(), refs)
	if err != nil {
		t.Fatal(err)
	}
	if err := to.Merge(t.Context(), muts); err != nil {
		t.Fatal(err)
	}
}

// A keyed read whose first replica has no row of it at all asks every
// replica and answers with the newest version: the row a replica missed is
// found, and an older copy on another replica does not win over a newer
// one (a used link, a revoked certificate, a deleted panel).
func TestKeyedReadsAskEveryReplicaOnAMiss(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	link := hashSecret("link-secret")
	device := func(name string) UpsertDevice {
		return UpsertDevice{
			ID: "pi", Name: name, Facts: "{}", Labels: "{}",
			FirstSeen: toMillis(now), LastSeen: toMillis(now), Status: StatusOnline,
		}
	}
	approval := CreateApproval{
		ID: "ap1", CreatedAt: toMillis(now), ExpiresAt: toMillis(now.Add(time.Hour)),
		ActorKind: "user", ActorID: "u", Action: "exec", Class: "dangerous", Target: "pi", Detail: "{}",
	}
	deviceRef := RowRef{Table: "devices", Key: Values{"pi"}}
	certRef := RowRef{Table: "certs", Key: Values{"0a"}}

	cases := []struct {
		name string
		// seed writes the first version on s, update the newer one.
		seed, update func(t *testing.T, rs replicaSet, s *Store)
		refs         []RowRef
		// check reads on a: the seeded version (newest false) or the
		// updated one; found false when nothing is seeded.
		check func(t *testing.T, a *Store, found, newest bool)
	}{
		{
			name: "approval link",
			seed: func(t *testing.T, rs replicaSet, s *Store) {
				rs.apply(t, s, approval)
				rs.apply(t, s, CreateApprovalLink{Hash: link[:], ApprovalID: "ap1", ExpiresAt: toMillis(now.Add(time.Hour))})
			},
			update: func(t *testing.T, rs replicaSet, s *Store) {
				rs.apply(t, s, UseApprovalLink{Hash: link[:], Now: toMillis(now)})
			},
			refs: []RowRef{{Table: "approvals", Key: Values{"ap1"}}, {Table: "approval_links", Key: Values{link[:]}}},
			check: func(t *testing.T, a *Store, found, newest bool) {
				id, err := a.ApprovalLinks().Peek(t.Context(), "link-secret", now)
				switch {
				case !found:
					if !errors.Is(err, ErrNotFound) {
						t.Fatalf("Peek = %q, %v, want not found", id, err)
					}
				case newest:
					if !errors.Is(err, ErrTokenUsed) {
						t.Fatalf("Peek = %q, %v, want used", id, err)
					}
				case err != nil || id != "ap1":
					t.Fatalf("Peek = %q, %v, want ap1", id, err)
				}
			},
		},
		{
			name: "approval",
			seed: func(t *testing.T, rs replicaSet, s *Store) { rs.apply(t, s, approval) },
			update: func(t *testing.T, rs replicaSet, s *Store) {
				rs.apply(t, s, DecideApproval{ID: "ap1", Status: ApprovalApproved, By: "admin", At: toMillis(now)})
			},
			refs: []RowRef{{Table: "approvals", Key: Values{"ap1"}}},
			check: func(t *testing.T, a *Store, found, newest bool) {
				ap, err := a.Approvals().Get(t.Context(), "ap1")
				want := ApprovalPending
				if newest {
					want = ApprovalApproved
				}
				switch {
				case !found:
					if !errors.Is(err, ErrNotFound) {
						t.Fatalf("Get = %+v, %v, want not found", ap, err)
					}
				case err != nil || ap.Status != want || ap.Target != "pi" || string(ap.Detail) != "{}":
					t.Fatalf("Get = %+v, %v, want %s", ap, err, want)
				}
			},
		},
		{
			name: "cert check",
			seed: func(t *testing.T, rs replicaSet, s *Store) {
				rs.apply(t, s, device("pi"))
				rs.apply(t, s, CreateCert{Serial: "0a", DeviceID: "pi", Fingerprint: "f1"})
			},
			update: func(t *testing.T, rs replicaSet, s *Store) {
				rs.apply(t, s, RevokeDevice{DeviceID: "pi", Now: toMillis(now)})
			},
			refs: []RowRef{deviceRef, certRef},
			check: func(t *testing.T, a *Store, found, newest bool) {
				err := a.Certs().Check(t.Context(), "0a", "pi")
				switch {
				case !found:
					if !errors.Is(err, ErrNotFound) {
						t.Fatalf("Check = %v, want not found", err)
					}
				case newest:
					if !errors.Is(err, ErrCertRevoked) {
						t.Fatalf("Check = %v, want revoked", err)
					}
				case err != nil:
					t.Fatalf("Check = %v", err)
				}
			},
		},
		{
			name: "cert pin",
			seed: func(t *testing.T, rs replicaSet, s *Store) {
				rs.apply(t, s, device("pi"))
				rs.apply(t, s, CreateCert{Serial: "0a", DeviceID: "pi"})
			},
			update: func(t *testing.T, rs replicaSet, s *Store) {
				rs.apply(t, s, PinCert{Serial: "0a", DeviceID: "pi", Fingerprint: "f1", Now: toMillis(now)})
			},
			refs: []RowRef{deviceRef, certRef},
			check: func(t *testing.T, a *Store, found, newest bool) {
				fp, err := a.Certs().Fingerprint(t.Context(), "0a", "pi")
				want := ""
				if newest {
					want = "f1"
				}
				switch {
				case !found:
					if !errors.Is(err, ErrNotFound) {
						t.Fatalf("Fingerprint = %q, %v, want not found", fp, err)
					}
				case err != nil || fp != want:
					t.Fatalf("Fingerprint = %q, %v, want %q", fp, err, want)
				}
			},
		},
		{
			name: "device route",
			seed: func(t *testing.T, rs replicaSet, s *Store) {
				rs.apply(t, s, SetDeviceRoute{DeviceID: "pi", Master: "m1", At: toMillis(now)})
			},
			update: func(t *testing.T, rs replicaSet, s *Store) {
				rs.apply(t, s, SetDeviceRoute{DeviceID: "pi", Master: "m2", At: toMillis(now) + 1})
			},
			refs: []RowRef{{Table: "device_routes", Key: Values{"pi"}}},
			check: func(t *testing.T, a *Store, found, newest bool) {
				r, err := a.DeviceRoutes().Get(t.Context(), "pi")
				want := "m1"
				if newest {
					want = "m2"
				}
				switch {
				case !found:
					if !errors.Is(err, ErrNotFound) {
						t.Fatalf("Get = %+v, %v, want not found", r, err)
					}
				case err != nil || r.Master != want:
					t.Fatalf("Get = %+v, %v, want %s", r, err, want)
				}
			},
		},
		{
			name: "device",
			seed: func(t *testing.T, rs replicaSet, s *Store) { rs.apply(t, s, device("old")) },
			update: func(t *testing.T, rs replicaSet, s *Store) {
				rs.apply(t, s, device("new"))
			},
			refs: []RowRef{deviceRef},
			check: func(t *testing.T, a *Store, found, newest bool) {
				d, err := a.Devices().Get(t.Context(), "pi")
				want := "old"
				if newest {
					want = "new"
				}
				switch {
				case !found:
					if !errors.Is(err, ErrNotFound) {
						t.Fatalf("Get = %+v, %v, want not found", d, err)
					}
				case err != nil || d.Name != want || !d.LastSeen.Equal(now):
					t.Fatalf("Get = %+v, %v, want %s", d, err, want)
				}
			},
		},
		{
			// The update deletes the panel: its tombstone on x wins over
			// y's older live copy. (A read that ignored tombstones would
			// bring the panel back.)
			name: "panel",
			seed: func(t *testing.T, rs replicaSet, s *Store) {
				rs.apply(t, s, CreatePanel{ID: "p1", Name: "Lab", Widgets: "[]", At: toMillis(now)})
			},
			update: func(t *testing.T, rs replicaSet, s *Store) { rs.apply(t, s, DeletePanel{ID: "p1"}) },
			refs:   []RowRef{{Table: "panels", Key: Values{"p1"}}},
			check: func(t *testing.T, a *Store, found, newest bool) {
				p, err := a.Panels().Get(t.Context(), "p1")
				switch {
				case !found || newest:
					if !errors.Is(err, ErrNotFound) {
						t.Fatalf("Get = %+v, %v, want not found", p, err)
					}
				case err != nil || p.Name != "Lab" || !p.CreatedAt.Equal(now):
					t.Fatalf("Get = %+v, %v, want Lab", p, err)
				}
			},
		},
	}
	for _, tc := range cases {
		for _, holder := range []string{"a", "b"} {
			t.Run(tc.name+"/holder "+holder, func(t *testing.T) {
				rs := newReplicaSet(t, holder)
				tc.check(t, rs.a, false, false)
				// Only x has the row: the first replica asked missed it.
				tc.seed(t, rs, rs.x)
				tc.check(t, rs.a, true, false)
				// y has the older version, x the newer one.
				copyRows(t, rs.x, rs.y, tc.refs)
				tc.update(t, rs, rs.x)
				tc.check(t, rs.a, true, true)
				// The first replica has caught up: it answers alone.
				copyRows(t, rs.x, rs.first, tc.refs)
				tc.check(t, rs.a, true, true)
			})
		}
	}
}
