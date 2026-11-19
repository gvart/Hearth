// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestCARotations(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	rots := s.CARotations()
	if _, err := rots.Latest(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Latest with none = %v, want ErrNotFound", err)
	}

	for _, id := range []string{"pi", "nas", "tv", "gone"} {
		if err := s.Devices().Upsert(ctx, Device{ID: id, FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	certs := s.Certs()
	must(certs.Record(ctx, CertRecord{Serial: "01", DeviceID: "pi", Fingerprint: "f1", CAFP: "old"}))
	must(certs.Create(ctx, "02", "nas")) // never pinned
	must(certs.Record(ctx, CertRecord{Serial: "03", DeviceID: "tv", Fingerprint: "f3", CAFP: "old"}))
	if _, err := certs.Pin(ctx, "03", "tv", "forged", "old", now); err != nil {
		t.Fatal(err)
	}
	must(certs.Record(ctx, CertRecord{Serial: "04", DeviceID: "gone", Fingerprint: "f4", CAFP: "old"}))
	if _, err := certs.RevokeDevice(ctx, "gone", now); err != nil {
		t.Fatal(err)
	}
	must(s.Hubs().RecordCert(ctx, "0a", "hub-a")) // recorded before fingerprints
	must(s.Hubs().Record(ctx, HubCert{Serial: "0b", NodeID: "hub-b", Fingerprint: "fb", CAFP: "old"}))

	unpinned, err := rots.Unpinned(ctx)
	must(err)
	want := []UnpinnedCert{
		{Kind: "device", ID: "nas", Serial: "02"},
		{Kind: "device", ID: "tv", Serial: "03", Mismatch: true},
		{Kind: "hub", ID: "hub-a", Serial: "0a"},
	}
	if !reflect.DeepEqual(unpinned, want) {
		t.Errorf("Unpinned = %+v, want %+v", unpinned, want)
	}

	// A device counts as moved to the new CA once it presented a
	// certificate of it, which pins its fingerprint; issuing one is not
	// enough.
	must(certs.Record(ctx, CertRecord{Serial: "11", DeviceID: "pi", CAFP: "new"}))
	old, err := rots.OldCADevices(ctx, "new")
	must(err)
	if !reflect.DeepEqual(old, []string{"nas", "pi", "tv"}) {
		t.Errorf("OldCADevices before pi presented its new cert = %v", old)
	}
	if got, err := certs.Pin(ctx, "11", "pi", "f11", "new", now); err != nil || got != Pinned {
		t.Fatalf("Pin(11) = %v, %v", got, err)
	}
	old, err = rots.OldCADevices(ctx, "new")
	must(err)
	if !reflect.DeepEqual(old, []string{"nas", "tv"}) {
		t.Errorf("OldCADevices = %v, want [nas tv]", old)
	}

	rot := CARotation{NewCAFP: "new", OldCAFP: "old", NewCACert: "pem", Pins: map[string]string{"hub-a": "fa", "hub-b": "fb"}}
	must(rots.Start(ctx, rot, now))
	got, err := rots.Active(ctx)
	must(err)
	rot.Stage, rot.StartedAt, rot.UpdatedAt = CAStageStarted, now, now
	if !reflect.DeepEqual(got, rot) {
		t.Errorf("Active = %+v, want %+v", got, rot)
	}
	if err := rots.Start(ctx, CARotation{NewCAFP: "other", OldCAFP: "old"}, now); !errors.Is(err, ErrCARotationActive) || !IsDomainError(err) {
		t.Errorf("a second Start = %v, want a domain ErrCARotationActive", err)
	}
	// Re-sealing is refused before the cutover.
	if err := rots.Reseal(ctx, "new", []SealedSecret{{Table: SealedKubeClusters, ID: "k1", Sealed: []byte{1}, Resealed: []byte{2}}}); !errors.Is(err, ErrCARotationConflict) {
		t.Errorf("Reseal before the cutover = %v, want ErrCARotationConflict", err)
	}
	for _, step := range [][2]string{{CAStageStarted, CAStageFinished}, {CAStageCutover, CAStageFinished}, {CAStageFinished, CAStageStarted}, {CAStageCutover, CAStageAborted}, {CAStageAborted, CAStageStarted}} {
		if err := rots.Advance(ctx, "new", step[0], step[1], now); !errors.Is(err, ErrCARotationConflict) {
			t.Errorf("Advance %s -> %s = %v, want ErrCARotationConflict", step[0], step[1], err)
		}
	}
	must(rots.Advance(ctx, "new", CAStageStarted, CAStageCutover, now))

	// Sealed secrets of every kind, re-sealed all or none.
	must(s.KubeClusters().Add(ctx, KubeCluster{ID: "k1", Name: "lab", Sealed: []byte{1}, CreatedAt: now}))
	must(s.ProxmoxServers().Add(ctx, ProxmoxServer{ID: "p1", Name: "rack", Sealed: []byte{2}, CreatedAt: now}))
	sealed, err := rots.Sealed(ctx)
	must(err)
	if len(sealed) != 2 || sealed[0].Table != SealedKubeClusters || sealed[1].Table != SealedProxmoxServers {
		t.Fatalf("Sealed = %+v", sealed)
	}
	sealed[0].Resealed, sealed[1].Resealed = []byte{11}, []byte{12}
	stale := append([]SealedSecret{}, sealed...)
	stale[1].Sealed = []byte{9}
	if err := rots.Reseal(ctx, "new", stale); !errors.Is(err, ErrCARotationConflict) {
		t.Errorf("Reseal of a changed secret = %v, want ErrCARotationConflict", err)
	}
	if again, _ := rots.Sealed(ctx); string(again[0].Sealed) != string([]byte{1}) {
		t.Errorf("a refused Reseal changed %s: %v", again[0].ID, again[0].Sealed)
	}
	if err := rots.Reseal(ctx, "new", []SealedSecret{{Table: "devices", ID: "pi", Sealed: []byte{1}, Resealed: []byte{2}}}); !errors.Is(err, ErrCARotationConflict) {
		t.Errorf("Reseal of another table = %v, want ErrCARotationConflict", err)
	}
	must(rots.Reseal(ctx, "new", sealed))
	again, err := rots.Sealed(ctx)
	must(err)
	if string(again[0].Sealed) != string([]byte{11}) || string(again[1].Sealed) != string([]byte{12}) {
		t.Errorf("after Reseal: %+v", again)
	}

	// Finishing names the sealed secrets checked: one sealed since refuses it.
	if err := rots.Advance(ctx, "new", CAStageCutover, CAStageFinished, now); !errors.Is(err, ErrCARotationConflict) {
		t.Errorf("finish without the sealed digest = %v, want ErrCARotationConflict", err)
	}
	checked := SealedDigest(again)
	must(s.KubeClusters().Add(ctx, KubeCluster{ID: "k2", Name: "late", Sealed: []byte{3}, CreatedAt: now}))
	if err := rots.Finish(ctx, "new", checked, now); !errors.Is(err, ErrCARotationConflict) {
		t.Errorf("finish after a secret was sealed since the check = %v, want ErrCARotationConflict", err)
	}
	again, err = rots.Sealed(ctx)
	must(err)
	must(rots.Finish(ctx, "new", SealedDigest(again), now))
	if _, err := rots.Active(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("Active after finish = %v, want ErrNotFound", err)
	}
	if latest, err := rots.Latest(ctx); err != nil || latest.Stage != CAStageFinished {
		t.Errorf("Latest after finish = %+v, %v", latest, err)
	}
	// Another rotation can start once one finished.
	must(rots.Start(ctx, CARotation{NewCAFP: "newer", OldCAFP: "new", Pins: map[string]string{}}, now.Add(time.Hour)))
	// Latest is the one started last, whatever the clocks say; an aborted one
	// is no longer under way, and once aborted it stays so.
	if latest, err := rots.Latest(ctx); err != nil || latest.NewCAFP != "newer" {
		t.Errorf("Latest = %+v, %v; want the one started last", latest, err)
	}
	// The abort revokes what the aborted CA issued, and nothing else.
	must(certs.Record(ctx, CertRecord{Serial: "a1", DeviceID: "pi", CAFP: "newer"}))
	must(s.Hubs().Record(ctx, HubCert{Serial: "a2", NodeID: "hub-b", Fingerprint: "fa2", CAFP: "newer"}))
	if renewed, err := rots.RenewedDevices(ctx, "newer"); err != nil || len(renewed) != 1 {
		t.Fatalf("RenewedDevices = %v, %v", renewed, err)
	}
	must(rots.Advance(ctx, "newer", CAStageStarted, CAStageAborted, now))
	if renewed, err := rots.RenewedDevices(ctx, "newer"); err != nil || len(renewed) != 0 {
		t.Errorf("devices of the aborted CA after the abort = %v, %v; want their certificates revoked", renewed, err)
	}
	hubCerts, err := s.Hubs().Certs(ctx, "hub-b")
	must(err)
	for _, c := range hubCerts {
		if c.Revoked != (c.CAFP == "newer") {
			t.Errorf("hub certificate %s of CA %s: revoked %v after the abort", c.Serial, c.CAFP, c.Revoked)
		}
	}
	if _, err := rots.Active(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("Active after abort = %v, want ErrNotFound", err)
	}
	if err := rots.Advance(ctx, "newer", CAStageStarted, CAStageCutover, now); !errors.Is(err, ErrCARotationConflict) {
		t.Errorf("cutover after abort = %v, want ErrCARotationConflict", err)
	}
	must(rots.Start(ctx, CARotation{NewCAFP: "newest", OldCAFP: "new", Pins: map[string]string{}}, now.Add(-time.Hour)))
	if latest, err := rots.Latest(ctx); err != nil || latest.NewCAFP != "newest" {
		t.Errorf("Latest after an earlier-clocked start = %+v, %v", latest, err)
	}
}

// Below CARotationSchema no rotation can be read or started: the command
// would halt a hub whose binary predates it.
func TestCARotationsBeforeSchema(t *testing.T) {
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
	if _, err := p.DownTo(ctx, CARotationSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.CARotations().Latest(ctx); !errors.Is(err, ErrSchemaTooOld) {
		t.Errorf("Latest before the schema = %v, want ErrSchemaTooOld", err)
	}
	err = s.CARotations().Start(ctx, CARotation{NewCAFP: "new", OldCAFP: "old", Pins: map[string]string{}}, time.Now())
	if !errors.Is(err, ErrSchemaTooOld) {
		t.Errorf("Start before the schema = %v, want ErrSchemaTooOld", err)
	}
}
