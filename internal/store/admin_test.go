// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestDevicesReportFactsKeepsEnrollmentFields(t *testing.T) {
	ctx := t.Context()
	devs := openTest(t).Devices()
	t0 := time.UnixMilli(1_700_000_000_000).UTC()
	t1 := t0.Add(time.Minute)
	enrolled := Device{
		ID: "pi", Name: "kitchen-pi", Hostname: "pi", Labels: map[string]string{"room": "attic"},
		FirstSeen: t0, LastSeen: t0, Status: StatusUnknown,
	}
	if err := devs.Upsert(ctx, enrolled); err != nil {
		t.Fatal(err)
	}

	got, prev, err := devs.ReportFacts(ctx, "pi", DeviceFacts{
		Hostname: "pi.lan", OS: "linux", Arch: "arm64", Facts: json.RawMessage(`{"cpu_cores":4}`),
	}, t1)
	if err != nil {
		t.Fatalf("ReportFacts: %v", err)
	}
	if prev != StatusUnknown {
		t.Errorf("prev status = %q, want %q", prev, StatusUnknown)
	}
	want := Device{
		ID: "pi", Name: "kitchen-pi", Hostname: "pi.lan", OS: "linux", Arch: "arm64",
		Facts: json.RawMessage(`{"cpu_cores":4}`), Labels: map[string]string{"room": "attic"},
		FirstSeen: t0, LastSeen: t1, Status: StatusOnline,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReportFacts = %+v, want %+v", got, want)
	}
	if stored, _ := devs.Get(ctx, "pi"); !reflect.DeepEqual(stored, want) {
		t.Fatalf("stored = %+v, want %+v", stored, want)
	}

	if _, _, err := devs.ReportFacts(ctx, "missing", DeviceFacts{}, t1); !errors.Is(err, ErrNotFound) {
		t.Errorf("ReportFacts(missing) err = %v, want ErrNotFound", err)
	}
	if _, _, err := devs.ReportFacts(ctx, "pi", DeviceFacts{Facts: json.RawMessage(`{`)}, t1); err == nil {
		t.Error("ReportFacts with invalid JSON: want error")
	}
}

func TestDevicesStatusTransitions(t *testing.T) {
	ctx := t.Context()
	devs := openTest(t).Devices()
	t0 := time.UnixMilli(1_700_000_000_000).UTC()
	for _, id := range []string{"a", "b", "c"} {
		if err := devs.Upsert(ctx, Device{ID: id, FirstSeen: t0, LastSeen: t0, Status: StatusUnknown}); err != nil {
			t.Fatal(err)
		}
	}

	// a and b come online at t0 and t0+20s; c never does.
	if _, prev, err := devs.MarkSeen(ctx, "a", t0); err != nil || prev != StatusUnknown {
		t.Fatalf("MarkSeen(a) prev=%q err=%v", prev, err)
	}
	if d, prev, err := devs.MarkSeen(ctx, "b", t0.Add(20*time.Second)); err != nil || prev != StatusUnknown ||
		d.Status != StatusOnline || !d.LastSeen.Equal(t0.Add(20*time.Second)) {
		t.Fatalf("MarkSeen(b) = %+v prev=%q err=%v", d, prev, err)
	}
	if _, _, err := devs.MarkSeen(ctx, "missing", t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("MarkSeen(missing) err = %v, want ErrNotFound", err)
	}

	// Cutoff t0+10s: only a was last seen before it. c is not online, so stays.
	off, err := devs.MarkOffline(ctx, t0.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(off) != 1 || off[0].ID != "a" || off[0].Status != StatusOffline {
		t.Fatalf("MarkOffline = %+v, want [a offline]", off)
	}
	// Idempotent: a is already offline.
	if off, err := devs.MarkOffline(ctx, t0.Add(10*time.Second)); err != nil || len(off) != 0 {
		t.Fatalf("second MarkOffline = %+v, %v; want none", off, err)
	}
	if c, _ := devs.Get(ctx, "c"); c.Status != StatusUnknown {
		t.Errorf("c status = %q, want unchanged %q", c.Status, StatusUnknown)
	}
	// offline -> online.
	if _, prev, err := devs.MarkSeen(ctx, "a", t0.Add(time.Minute)); err != nil || prev != StatusOffline {
		t.Fatalf("MarkSeen(a) again prev=%q err=%v, want offline", prev, err)
	}
}

func TestAdminPassword(t *testing.T) {
	ctx := t.Context()
	adm := openTest(t).Admin()
	if _, err := adm.PasswordHash(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("PasswordHash before set: err = %v, want ErrNotFound", err)
	}
	if err := adm.SetPasswordHash(ctx, ""); err == nil {
		t.Fatal("SetPasswordHash(empty): want error")
	}
	for _, h := range []string{"hash-1", "hash-2"} {
		if err := adm.SetPasswordHash(ctx, h); err != nil {
			t.Fatal(err)
		}
		if got, err := adm.PasswordHash(ctx); err != nil || got != h {
			t.Fatalf("PasswordHash = %q, %v; want %q", got, err, h)
		}
	}
}

func TestAdminSessions(t *testing.T) {
	ctx := t.Context()
	adm := openTest(t).Admin()
	now := time.UnixMilli(1_700_000_000_000).UTC()
	exp := now.Add(time.Hour)
	if err := adm.CreateSession(ctx, "", now, exp); err == nil {
		t.Fatal("CreateSession(empty): want error")
	}
	if err := adm.CreateSession(ctx, "s1", now, exp); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		secret string
		at     time.Time
		want   error
	}{
		{"valid", "s1", now, nil},
		{"just before expiry", "s1", exp.Add(-time.Millisecond), nil},
		{"at expiry", "s1", exp, ErrSessionExpired},
		{"after expiry", "s1", exp.Add(time.Hour), ErrSessionExpired},
		{"unknown", "nope", now, ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := adm.CheckSession(ctx, tt.secret, tt.at)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if err == nil && !got.Equal(exp) {
				t.Errorf("expires = %v, want %v", got, exp)
			}
		})
	}

	if err := adm.DeleteSession(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := adm.CheckSession(ctx, "s1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: err = %v, want ErrNotFound", err)
	}

	// Resetting the password ends every session.
	if err := adm.CreateSession(ctx, "s2", now, exp); err != nil {
		t.Fatal(err)
	}
	if err := adm.SetPasswordHash(ctx, "new"); err != nil {
		t.Fatal(err)
	}
	if _, err := adm.CheckSession(ctx, "s2", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after password reset: err = %v, want ErrNotFound", err)
	}
}
