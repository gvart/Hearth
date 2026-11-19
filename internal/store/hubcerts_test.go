// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestHubCerts(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	hubs := s.Hubs()
	now := time.UnixMilli(1_700_000_000_000)

	for _, c := range []struct{ serial, node string }{{"01", "hub-a"}, {"02", "hub-a"}, {"03", "hub-b"}} {
		if err := hubs.RecordCert(ctx, c.serial, c.node); err != nil {
			t.Fatalf("RecordCert(%s): %v", c.serial, err)
		}
	}
	if err := hubs.RecordCert(ctx, "", "hub-a"); err == nil {
		t.Error("RecordCert empty serial: want error")
	}
	// An unrecorded serial is not refused: revocation is a deny list.
	if err := hubs.CheckCert(ctx, "ff"); err != nil {
		t.Errorf("CheckCert(unrecorded) = %v, want nil", err)
	}

	n, err := hubs.RevokeCerts(ctx, "hub-a", now)
	if err != nil || n != 2 {
		t.Fatalf("RevokeCerts(hub-a) = %d, %v; want 2, nil", n, err)
	}
	for _, serial := range []string{"01", "02"} {
		if err := hubs.CheckCert(ctx, serial); !errors.Is(err, ErrCertRevoked) {
			t.Errorf("CheckCert(%s) = %v, want ErrCertRevoked", serial, err)
		}
	}
	if err := hubs.CheckCert(ctx, "03"); err != nil {
		t.Errorf("CheckCert(03) of another hub = %v, want nil", err)
	}
	// Revoking again is a no-op; so is an unknown node.
	for _, id := range []string{"hub-a", "ghost"} {
		if n, err := hubs.RevokeCerts(ctx, id, now); err != nil || n != 0 {
			t.Errorf("RevokeCerts(%s) again = %d, %v; want 0, nil", id, n, err)
		}
	}
	// Recording a revoked serial again never clears its revocation.
	if err := hubs.RecordCert(ctx, "01", "hub-a"); err != nil {
		t.Fatal(err)
	}
	if err := hubs.CheckCert(ctx, "01"); !errors.Is(err, ErrCertRevoked) {
		t.Errorf("CheckCert(01) after recording it again = %v, want ErrCertRevoked", err)
	}
	// A rejoin under the same node ID gets a new, valid serial.
	if err := hubs.RecordCert(ctx, "04", "hub-a"); err != nil {
		t.Fatal(err)
	}
	if err := hubs.CheckCert(ctx, "04"); err != nil {
		t.Errorf("CheckCert(new serial) = %v, want nil", err)
	}
	got, err := hubs.Certs(ctx, "hub-a")
	if err != nil {
		t.Fatal(err)
	}
	want := []HubCert{{Serial: "01", NodeID: "hub-a", Revoked: true}, {Serial: "02", NodeID: "hub-a", Revoked: true}, {Serial: "04", NodeID: "hub-a"}}
	if !slices.Equal(got, want) {
		t.Errorf("Certs(hub-a) = %+v, want %+v", got, want)
	}
}

// TestHubCertsBeforeTheirSchema (#95): a newer binary on a cluster database
// still at schema 5, before `hearth cluster migrate` adds hub_certs. There is
// no deny list yet, so reads see nothing revoked; writes are refused, the
// same way on every node, until the migrate.
func TestHubCertsBeforeTheirSchema(t *testing.T) {
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
	if _, err := p.DownTo(ctx, hubCertsSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if v := gooseVersion(t, s.db); v != hubCertsSchema-1 {
		t.Fatalf("database at %d, want %d", v, hubCertsSchema-1)
	}
	hubs := s.Hubs()
	now := time.UnixMilli(1_700_000_000_000)

	if err := hubs.CheckCert(ctx, "01"); err != nil {
		t.Errorf("CheckCert before the schema = %v, want nil", err)
	}
	if certs, err := hubs.Certs(ctx, "hub-a"); err != nil || len(certs) != 0 {
		t.Errorf("Certs before the schema = %v, %v; want none", certs, err)
	}
	if err := hubs.RequireCerts(ctx); !errors.Is(err, ErrSchemaTooOld) {
		t.Errorf("RequireCerts before the schema = %v, want ErrSchemaTooOld", err)
	}
	_, revokeErr := hubs.RevokeCerts(ctx, "hub-a", now)
	for name, err := range map[string]error{
		"RecordCert":  hubs.RecordCert(ctx, "01", "hub-a"),
		"RevokeCerts": revokeErr,
	} {
		// A domain error: the FSM rolls it back on every node instead of
		// halting.
		if !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) ||
			!strings.Contains(err.Error(), "hearth cluster migrate") {
			t.Errorf("%s before the schema = %v, want ErrSchemaTooOld telling to migrate", name, err)
		}
	}

	if _, err := s.ApplyLocal(ctx, MigrateSchema{To: hubCertsSchema}); err != nil {
		t.Fatalf("migrate to %d: %v", hubCertsSchema, err)
	}
	if err := hubs.RequireCerts(ctx); err != nil {
		t.Fatalf("RequireCerts after the migrate = %v", err)
	}
	if err := hubs.RecordCert(ctx, "01", "hub-a"); err != nil {
		t.Fatalf("RecordCert after the migrate: %v", err)
	}
	if n, err := hubs.RevokeCerts(ctx, "hub-a", now); err != nil || n != 1 {
		t.Fatalf("RevokeCerts after the migrate = %d, %v; want 1, nil", n, err)
	}
	if err := hubs.CheckCert(ctx, "01"); !errors.Is(err, ErrCertRevoked) {
		t.Errorf("CheckCert after the revoke = %v, want ErrCertRevoked", err)
	}
	if certs, err := hubs.Certs(ctx, "hub-a"); err != nil || len(certs) != 1 || !certs[0].Revoked {
		t.Errorf("Certs after the revoke = %v, %v", certs, err)
	}
}
