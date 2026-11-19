// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestCertFingerprints(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	now := time.UnixMilli(1_700_000_000_000)
	for _, id := range []string{"pi", "nas"} {
		if err := s.Devices().Upsert(ctx, Device{ID: id, FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	certs := s.Certs()
	if err := certs.Record(ctx, CertRecord{Serial: "01", DeviceID: "pi", Fingerprint: "fp1", CAFP: "ca1"}); err != nil {
		t.Fatal(err)
	}
	// Issued before fingerprints were recorded.
	if err := certs.Create(ctx, "02", "nas"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		serial, dev, want string
		err               error
	}{
		{"01", "pi", "fp1", nil},
		{"02", "nas", "", nil},
		{"01", "nas", "", ErrNotFound},
		{"ff", "pi", "", ErrNotFound},
	}
	for _, tt := range tests {
		if got, err := certs.Fingerprint(ctx, tt.serial, tt.dev); got != tt.want || !errors.Is(err, tt.err) {
			t.Errorf("Fingerprint(%s, %s) = %q, %v; want %q, %v", tt.serial, tt.dev, got, err, tt.want, tt.err)
		}
	}

	// Trust on first use: only a certificate without a fingerprint is
	// pinned, and only once; another certificate is a mismatch, recorded the
	// first time it is seen.
	pins := []struct {
		serial, dev, fp string
		want            PinOutcome
		err             error
		recorded        string
	}{
		{"02", "nas", "fp2", Pinned, nil, "fp2"},
		{"02", "nas", "fp2", PinKept, nil, "fp2"},
		{"02", "nas", "forged", PinMismatch, nil, "fp2"},
		{"02", "nas", "forged", PinKept, nil, "fp2"},
		{"01", "pi", "fp1", PinKept, nil, "fp1"},
		{"01", "nas", "fp1", PinKept, ErrNotFound, ""}, // another device's certificate
	}
	for _, p := range pins {
		got, err := certs.Pin(ctx, p.serial, p.dev, p.fp, "ca2", now)
		if !errors.Is(err, p.err) || got != p.want {
			t.Errorf("Pin(%s, %s, %s) = %v, %v; want %v, %v", p.serial, p.dev, p.fp, got, err, p.want, p.err)
		}
		if p.recorded == "" {
			continue
		}
		if fp, _ := certs.Fingerprint(ctx, p.serial, p.dev); fp != p.recorded {
			t.Errorf("after Pin(%s, %s): fingerprint %q, want %q", p.serial, p.dev, fp, p.recorded)
		}
	}
	if got, err := certs.PinMismatches(ctx, "nas"); err != nil || len(got) != 1 || got[0] != "02" {
		t.Errorf("PinMismatches(nas) = %v, %v; want [02]", got, err)
	}
	if got, err := certs.PinMismatches(ctx, "pi"); err != nil || len(got) != 0 {
		t.Errorf("PinMismatches(pi) = %v, %v; want none", got, err)
	}
	var caFP string
	if err := s.db.QueryRowContext(ctx, `SELECT ca_fp FROM certs WHERE serial = '02'`).Scan(&caFP); err != nil || caFP != "ca2" {
		t.Errorf("pinned certificate's ca_fp = %q, %v; want ca2", caFP, err)
	}
	if _, err := certs.Pin(ctx, "02", "nas", "", "", now); err == nil {
		t.Error("Pin with no fingerprint: want error")
	}
}

func TestHubCertFingerprints(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	hubs := s.Hubs()
	if err := hubs.RecordCert(ctx, "01", "hub-a"); err != nil {
		t.Fatal(err)
	}
	if err := hubs.Record(ctx, HubCert{Serial: "02", NodeID: "hub-a", Fingerprint: "fp2", CAFP: "ca"}); err != nil {
		t.Fatal(err)
	}
	// A serial recorded without fingerprints gets them; one recorded with
	// them keeps them; another node cannot take a serial over.
	for _, c := range []HubCert{
		{Serial: "01", NodeID: "hub-a", Fingerprint: "fp1", CAFP: "ca"},
		{Serial: "02", NodeID: "hub-a", Fingerprint: "other", CAFP: "other"},
		{Serial: "01", NodeID: "hub-b", Fingerprint: "evil", CAFP: "evil"},
	} {
		if err := hubs.Record(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hubs.RevokeCerts(ctx, "hub-a", time.UnixMilli(1)); err != nil {
		t.Fatal(err)
	}
	if err := hubs.Record(ctx, HubCert{Serial: "01", NodeID: "hub-a", Fingerprint: "fp1"}); err != nil {
		t.Fatal(err)
	}
	got, err := hubs.Certs(ctx, "hub-a")
	if err != nil {
		t.Fatal(err)
	}
	want := []HubCert{
		{Serial: "01", NodeID: "hub-a", Revoked: true, Fingerprint: "fp1", CAFP: "ca"},
		{Serial: "02", NodeID: "hub-a", Revoked: true, Fingerprint: "fp2", CAFP: "ca"},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Certs(hub-a) = %+v, want %+v", got, want)
	}
	if got, _ := hubs.Certs(ctx, "hub-b"); len(got) != 0 {
		t.Errorf("Certs(hub-b) = %+v, want none", got)
	}
}

// Below CertPinsSchema the fingerprints are not recorded and nothing is pinned,
// the same way on every node.
func TestCertFingerprintsBeforeSchema(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "hearth.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.newMigrator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, CertPinsSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	var proposed []Command
	s, err = Open(ctx, path, WithoutUpgrade(), WithApplier(func(s *Store) Applier {
		return ApplierFunc(func(ctx context.Context, cmd Command) (Result, error) {
			proposed = append(proposed, cmd)
			return s.ApplyLocal(ctx, cmd)
		})
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if s.AtSchema(ctx, CertPinsSchema) {
		t.Fatal("AtSchema(CertPinsSchema) below it = true")
	}

	now := time.UnixMilli(1_700_000_000_000)
	if err := s.Devices().Upsert(ctx, Device{ID: "pi", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.Certs().Record(ctx, CertRecord{Serial: "01", DeviceID: "pi", Fingerprint: "fp", CAFP: "ca"}); err != nil {
		t.Fatalf("Record before the schema: %v", err)
	}
	if err := s.Hubs().Record(ctx, HubCert{Serial: "0a", NodeID: "hub-a", Fingerprint: "fp", CAFP: "ca"}); err != nil {
		t.Fatalf("Hubs.Record before the schema: %v", err)
	}
	// The commands carry no fingerprint: a hub that predates them could not
	// decode them.
	for _, cmd := range proposed {
		switch c := cmd.(type) {
		case CreateCert:
			if c.Fingerprint != "" || c.CAFP != "" {
				t.Errorf("proposed %+v before the schema, want no fingerprints", c)
			}
		case RecordHubCert:
			if c.Fingerprint != "" || c.CAFP != "" {
				t.Errorf("proposed %+v before the schema, want no fingerprints", c)
			}
		}
	}
	if err := s.Certs().Check(ctx, "01", "pi"); err != nil {
		t.Errorf("Check = %v, want nil", err)
	}
	if _, err := s.Certs().Fingerprint(ctx, "01", "pi"); !errors.Is(err, ErrSchemaTooOld) {
		t.Errorf("Fingerprint before the schema = %v, want ErrSchemaTooOld", err)
	}
	if _, err := s.Certs().Pin(ctx, "01", "pi", "fp", "ca", now); !errors.Is(err, ErrSchemaTooOld) {
		t.Errorf("Pin before the schema = %v, want ErrSchemaTooOld", err)
	}
	for _, cmd := range proposed {
		if _, ok := cmd.(PinCert); ok {
			t.Error("Pin proposed pin_cert before the schema")
		}
	}
	if got, err := s.Hubs().Certs(ctx, "hub-a"); err != nil || len(got) != 1 || got[0].Fingerprint != "" {
		t.Errorf("Hubs.Certs before the schema = %+v, %v; want 0a without a fingerprint", got, err)
	}
	// A command with fingerprints from a newer leader applies without them.
	for _, cmd := range []Command{
		CreateCert{Serial: "02", DeviceID: "pi", Fingerprint: "fp", CAFP: "ca"},
		RecordHubCert{Serial: "0b", NodeID: "hub-a", Fingerprint: "fp", CAFP: "ca"},
	} {
		if _, err := s.ApplyLocal(ctx, cmd); err != nil {
			t.Errorf("ApplyLocal(%s) before the schema = %v, want nil", cmd.Op(), err)
		}
	}
}
