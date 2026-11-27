// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCerts(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	certs := s.Certs()
	now := time.UnixMilli(1_700_000_000_000)

	if err := certs.Create(ctx, "aa", "ghost"); err == nil {
		t.Fatal("Create for unknown device: want foreign key error")
	}
	for _, id := range []string{"pi", "nas"} {
		if err := s.Devices().Upsert(ctx, Device{ID: id, FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct{ serial, dev string }{{"01", "pi"}, {"02", "pi"}, {"03", "nas"}} {
		if err := certs.Create(ctx, c.serial, c.dev); err != nil {
			t.Fatalf("Create(%s): %v", c.serial, err)
		}
	}
	if err := certs.Create(ctx, "01", "pi"); err == nil {
		t.Error("Create duplicate serial: want error")
	}
	if err := certs.Create(ctx, "", "pi"); err == nil {
		t.Error("Create empty serial: want error")
	}

	n, err := certs.RevokeDevice(ctx, "pi", now)
	if err != nil || n != 2 {
		t.Fatalf("RevokeDevice(pi) = %d, %v; want 2, nil", n, err)
	}
	if n, err := certs.RevokeDevice(ctx, "pi", now); err != nil || n != 0 {
		t.Errorf("RevokeDevice(pi) again = %d, %v; want 0, nil", n, err)
	}
	if _, err := certs.RevokeDevice(ctx, "ghost", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("RevokeDevice(ghost) err = %v, want ErrNotFound", err)
	}

	tests := []struct {
		serial, dev string
		want        error
	}{
		{"03", "nas", nil},
		{"01", "pi", ErrCertRevoked},
		{"02", "pi", ErrCertRevoked},
		{"03", "pi", ErrNotFound}, // issued to another device
		{"ff", "nas", ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.serial+"/"+tt.dev, func(t *testing.T) {
			if err := certs.Check(ctx, tt.serial, tt.dev); !errors.Is(err, tt.want) {
				t.Errorf("Check = %v, want %v", err, tt.want)
			}
		})
	}
}

// unavailableShards answers no read: no replica is reachable.
type unavailableShards struct{ fakeShards }

func (unavailableShards) ReadReplicas(context.Context, string, string, Values) ([]Rows, error) {
	return nil, ErrUnavailable
}

// A certificate check in a sharded cluster asks every replica, and a
// revocation any one of them holds wins (#387): a replica that answers "not
// revoked" (stale, or forged with a later version, as a compromised
// storage-only member may) or has no row at all does not let a revoked
// device in, whichever replica is asked first.
func TestCertCheckDenyWins(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	device := UpsertDevice{
		ID: "pi", Name: "pi", Facts: "{}", Labels: "{}",
		FirstSeen: toMillis(now), LastSeen: toMillis(now), Status: StatusOnline,
	}
	refs := []RowRef{{Table: "devices", Key: Values{"pi"}}, {Table: "certs", Key: Values{"0a"}}}
	// forge rewrites s's copy of the certificate as not revoked, at a
	// version newer than any honest one: what a compromised member's
	// database may hold, written without going through Merge.
	forge := func(t *testing.T, s *Store) {
		t.Helper()
		if _, err := s.db.ExecContext(t.Context(),
			`UPDATE certs SET revoked_at = NULL, _hlc = _hlc + 1000000, _origin = 'zz' WHERE serial = '0a'`); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name string
		// setup leaves rs.x with the revocation, and the other replicas as
		// the case says.
		setup func(t *testing.T, rs replicaSet)
		want  error
	}{
		{
			name: "first replica stale, not revoked",
			setup: func(t *testing.T, rs replicaSet) {
				copyRows(t, rs.x, rs.first, refs)
				copyRows(t, rs.x, rs.y, refs)
				rs.apply(t, rs.x, RevokeDevice{DeviceID: "pi", Now: toMillis(now)})
			},
			want: ErrCertRevoked,
		},
		{
			name: "first replica forged a newer unrevoked version",
			setup: func(t *testing.T, rs replicaSet) {
				rs.apply(t, rs.x, RevokeDevice{DeviceID: "pi", Now: toMillis(now)})
				copyRows(t, rs.x, rs.first, refs)
				copyRows(t, rs.x, rs.y, refs)
				forge(t, rs.first)
				forge(t, rs.y)
			},
			want: ErrCertRevoked,
		},
		{
			name: "other replicas have no row",
			setup: func(t *testing.T, rs replicaSet) {
				rs.apply(t, rs.x, RevokeDevice{DeviceID: "pi", Now: toMillis(now)})
			},
			want: ErrCertRevoked,
		},
		{
			name: "no replica revoked it",
			setup: func(t *testing.T, rs replicaSet) {
				copyRows(t, rs.x, rs.first, refs)
			},
			want: nil,
		},
	}
	for _, tc := range cases {
		for _, holder := range []string{"a", "b"} {
			t.Run(tc.name+"/holder "+holder, func(t *testing.T) {
				rs := newReplicaSet(t, holder)
				if err := rs.a.Certs().Check(t.Context(), "0a", "pi"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("Check with no replica holding the row = %v, want ErrNotFound", err)
				}
				rs.apply(t, rs.x, device)
				rs.apply(t, rs.x, CreateCert{Serial: "0a", DeviceID: "pi", Fingerprint: "f1"})
				tc.setup(t, rs)
				if err := rs.a.Certs().Check(t.Context(), "0a", "pi"); !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
					t.Fatalf("Check = %v, want %v", err, tc.want)
				}
			})
		}
	}

	// No replica reachable: the check fails, neither "unknown" nor "revoked".
	a := openTestWith(t, WithShards(&unavailableShards{fakeShards{self: "a", key: func(string) string { return "b" }}}))
	err := a.Certs().Check(t.Context(), "0a", "pi")
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrCertRevoked) {
		t.Fatalf("Check with no replica reachable = %v, want ErrUnavailable", err)
	}
}
