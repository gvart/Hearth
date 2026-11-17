// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"slices"
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
	want := []HubCert{{"01", "hub-a", true}, {"02", "hub-a", true}, {"04", "hub-a", false}}
	if !slices.Equal(got, want) {
		t.Errorf("Certs(hub-a) = %+v, want %+v", got, want)
	}
}
