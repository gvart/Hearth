// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
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
