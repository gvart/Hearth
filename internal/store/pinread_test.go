// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/hlc"
)

// A certificate's fingerprint read in a sharded cluster asks every replica
// (#387): a replica that answers with another fingerprint, as a compromised
// storage-only member would for a certificate minted with the CA key, is
// refused rather than believed, whichever replica is asked first; one that
// answers with none (stale, or forged to have the certificate pinned again)
// does not hide the fingerprint the others hold. A later version naming
// another fingerprint, merged into the honest replicas, does not replace
// theirs: the fingerprint is set once.
func TestCertFingerprintForgedReplica(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	device := UpsertDevice{
		ID: "pi", Name: "pi", Facts: "{}", Labels: "{}",
		FirstSeen: toMillis(now), LastSeen: toMillis(now), Status: StatusOnline,
	}
	certRef := RowRef{Table: "certs", Key: Values{"0a"}}
	refs := []RowRef{{Table: "devices", Key: Values{"pi"}}, certRef}
	// forge rewrites s's own copy, without going through Merge, at a
	// version newer than any honest one: what a compromised member's
	// database may hold.
	forge := func(t *testing.T, s *Store, fp any) {
		t.Helper()
		if _, err := s.db.ExecContext(t.Context(),
			`UPDATE certs SET fingerprint = ?, _hlc = _hlc + 1000000, _origin = 'zz' WHERE serial = '0a'`, fp); err != nil {
			t.Fatal(err)
		}
	}
	// mergeForged merges into each of into the row a forger would send: the
	// certificate with another fingerprint, at a newer version.
	mergeForged := func(t *testing.T, from *Store, into ...*Store) {
		t.Helper()
		ms, err := from.ReadRows(t.Context(), []RowRef{certRef})
		if err != nil || len(ms) != 1 {
			t.Fatalf("read the certificate: %v, %v", ms, err)
		}
		ms[0].Row["fingerprint"], ms[0].HLC, ms[0].Origin = "evil", ms[0].HLC+1000000, "zz"
		for _, s := range into {
			if err := s.Merge(t.Context(), ms); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []struct {
		name string
		// setup starts with rs.first, rs.x and rs.y holding the certificate
		// pinned to f1, and returns the replica it forged, if any.
		setup   func(t *testing.T, rs replicaSet) *Store
		want    string
		wantErr error
	}{
		{name: "all agree", want: "f1"},
		{
			name:    "first replica forged another fingerprint",
			setup:   func(t *testing.T, rs replicaSet) *Store { forge(t, rs.first, "evil"); return rs.first },
			wantErr: ErrPinDisagreement,
		},
		{
			name:    "another replica forged another fingerprint",
			setup:   func(t *testing.T, rs replicaSet) *Store { forge(t, rs.y, "evil"); return rs.y },
			wantErr: ErrPinDisagreement,
		},
		{
			name:  "first replica forged no fingerprint",
			setup: func(t *testing.T, rs replicaSet) *Store { forge(t, rs.first, nil); return rs.first },
			want:  "f1",
		},
		{
			name: "a forged fingerprint merged into every replica",
			setup: func(t *testing.T, rs replicaSet) *Store {
				mergeForged(t, rs.x, rs.first, rs.x, rs.y)
				return nil
			},
			wantErr: ErrPinDisagreement,
		},
		{
			// The others' copies moved to another device by a newer version,
			// so that only the forger's answers for pi: its word does not
			// stand alone.
			name: "the certificate moved to another device by a merge",
			setup: func(t *testing.T, rs replicaSet) *Store {
				moveCert(t, rs.x, rs.x, rs.y)
				forge(t, rs.first, "evil")
				return rs.first
			},
			wantErr: ErrPinDisagreement,
		},
		{
			name: "a forged fingerprint merged into one replica",
			setup: func(t *testing.T, rs replicaSet) *Store {
				mergeForged(t, rs.x, rs.y)
				return nil
			},
			wantErr: ErrPinDisagreement,
		},
	}
	for _, tc := range cases {
		for _, holder := range []string{"a", "b"} {
			t.Run(tc.name+"/holder "+holder, func(t *testing.T) {
				rs := newReplicaSet(t, holder)
				if _, err := rs.a.Certs().Fingerprint(t.Context(), "0a", "pi"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("Fingerprint with no replica holding the row = %v, want ErrNotFound", err)
				}
				rs.apply(t, rs.x, device)
				rs.apply(t, rs.x, CreateCert{Serial: "0a", DeviceID: "pi", Fingerprint: "f1"})
				copyRows(t, rs.x, rs.first, refs)
				copyRows(t, rs.x, rs.y, refs)
				var forged *Store
				if tc.setup != nil {
					forged = tc.setup(t, rs)
				}
				fp, err := rs.a.Certs().Fingerprint(t.Context(), "0a", "pi")
				if tc.wantErr != nil {
					if !errors.Is(err, tc.wantErr) || fp != "" {
						t.Fatalf("Fingerprint = %q, %v, want %v", fp, err, tc.wantErr)
					}
				} else if err != nil || fp != tc.want {
					t.Fatalf("Fingerprint = %q, %v, want %q", fp, err, tc.want)
				}
				// No honest copy took the forged fingerprint.
				for _, s := range []*Store{rs.first, rs.x, rs.y} {
					if s == forged {
						continue
					}
					var got string
					if err := s.db.QueryRowContext(t.Context(), `SELECT fingerprint FROM certs WHERE serial = '0a'`).Scan(&got); err != nil {
						t.Fatal(err)
					}
					if got == "evil" {
						t.Errorf("%s's copy took the forged fingerprint", s.origin)
					}
				}
			})
		}
	}
}

// moveCert merges into each of into what a forger would send to hide
// certificate 0a of pi from a check by device: a newer version of it naming
// another device, evil, and that device's row for the foreign key.
func moveCert(t *testing.T, from *Store, into ...*Store) {
	t.Helper()
	ms, err := from.ReadRows(t.Context(), []RowRef{{Table: "devices", Key: Values{"pi"}}, {Table: "certs", Key: Values{"0a"}}})
	if err != nil || len(ms) != 2 {
		t.Fatalf("read the device and its certificate: %v, %v", ms, err)
	}
	for i := range ms {
		ms[i].HLC, ms[i].Origin = ms[i].HLC+1000000, "zz"
		if ms[i].Table == "devices" {
			ms[i].Row["id"] = "evil"
		} else {
			ms[i].Row["device_id"] = "evil"
		}
	}
	for _, s := range into {
		if err := s.Merge(t.Context(), ms); err != nil {
			t.Fatal(err)
		}
	}
}

// Two different fingerprints of one certificate merge into a conflict,
// whatever their versions' order, and a fingerprint merges into a copy
// without one, never out of it (#387).
func TestFingerprintMergesSetOnce(t *testing.T) {
	base := hlc.New(time.UnixMilli(1_700_000_000_000))
	cert := func(fp any, at hlc.Timestamp, origin string) Mutation {
		return Mutation{Table: "certs", HLC: base + at, Origin: origin, Row: map[string]any{
			"serial": "0a", "device_id": "pi", "fingerprint": fp, "ca_fp": nil, "revoked_at": nil, "pin_mismatch_at": nil,
		}}
	}
	for _, tc := range []struct {
		name string
		muts []Mutation
		want string
	}{
		{"unpinned, then pinned", []Mutation{cert(nil, 1, "a"), cert("f1", 2, "a")}, "f1"},
		{"pinned, then an older unpinned", []Mutation{cert("f1", 2, "a"), cert(nil, 1, "a")}, "f1"},
		{"pinned, then a newer unpinned", []Mutation{cert("f1", 1, "a"), cert(nil, 2, "zz")}, "f1"},
		{"pinned, then a newer other", []Mutation{cert("f1", 1, "a"), cert("evil", 2, "zz")}, pinConflict},
		{"other, then an older pinned", []Mutation{cert("evil", 2, "zz"), cert("f1", 1, "a")}, pinConflict},
		{"a conflict stays", []Mutation{cert("f1", 1, "a"), cert("evil", 2, "zz"), cert("f1", 3, "a")}, pinConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			s := openTest(t)
			if _, err := s.ApplyLocal(ctx, UpsertDevice{ID: "pi", Name: "pi", Facts: "{}", Labels: "{}", Status: StatusOnline}); err != nil {
				t.Fatal(err)
			}
			for _, m := range tc.muts {
				if err := s.Merge(ctx, []Mutation{m}); err != nil {
					t.Fatal(err)
				}
			}
			var got string
			if err := s.db.QueryRowContext(ctx, `SELECT fingerprint FROM certs WHERE serial = '0a'`).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("fingerprint %q, want %q", got, tc.want)
			}
			if fp, err := s.Certs().Fingerprint(ctx, "0a", "pi"); tc.want == pinConflict && !errors.Is(err, ErrPinDisagreement) {
				t.Fatalf("Fingerprint of a conflict = %q, %v, want ErrPinDisagreement", fp, err)
			}
		})
	}
}
