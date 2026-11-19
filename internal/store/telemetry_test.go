// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestTelemetrySetting(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	at := time.UnixMilli(1_700_000_000_000).UTC()

	got, err := s.Telemetry().Get(ctx)
	if err != nil || got != (TelemetrySetting{}) {
		t.Fatalf("Get before an answer = %+v, %v; want unanswered", got, err)
	}
	for _, tt := range []struct {
		name      string
		enabled   bool
		installID string
	}{
		{"on without an ID", true, ""},
		{"off with an ID", false, "abc"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.Telemetry().Set(ctx, tt.enabled, tt.installID, at); err == nil {
				t.Error("Set succeeded, want an error")
			}
		})
	}

	if err := s.Telemetry().Set(ctx, false, "", at); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Telemetry().Get(ctx); !got.Answered || got.Enabled || got.InstallID != "" {
		t.Errorf("after no = %+v, want answered and off", got)
	}
	if err := s.Telemetry().MarkSent(ctx, "", at); !errors.Is(err, ErrNotFound) {
		t.Errorf("MarkSent while off = %v, want ErrNotFound", err)
	}

	if err := s.Telemetry().Set(ctx, true, "id-1", at); err != nil {
		t.Fatal(err)
	}
	if err := s.Telemetry().MarkSent(ctx, "id-1", at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	want := TelemetrySetting{Answered: true, Enabled: true, InstallID: "id-1", LastSent: at.Add(time.Minute)}
	if got, _ := s.Telemetry().Get(ctx); got != want {
		t.Errorf("after a send = %+v, want %+v", got, want)
	}
	if err := s.Telemetry().MarkSent(ctx, "id-0", at); !errors.Is(err, ErrNotFound) {
		t.Errorf("MarkSent for another ID = %v, want ErrNotFound", err)
	}
	// A new answer resets the last send, so a new opt-in sends shortly after.
	if err := s.Telemetry().Set(ctx, true, "id-2", at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Telemetry().Get(ctx); !got.LastSent.IsZero() || got.InstallID != "id-2" {
		t.Errorf("after a new opt-in = %+v, want id-2 never sent", got)
	}
}

func TestTelemetryCounts(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	for _, id := range []string{"a", "b", "c"} {
		if err := s.Devices().Upsert(ctx, Device{ID: id, Name: id, Status: StatusOnline}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.KubeClusters().Add(ctx, KubeCluster{ID: "k", Name: "lab", Sealed: []byte{1}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Telemetry().Counts(ctx)
	if want := (TelemetryCounts{Devices: 3, KubeClusters: 1}); err != nil || got != want {
		t.Errorf("Counts = %+v, %v; want %+v", got, err, want)
	}
}

// Before the schema that added the table the admin has not answered, and no
// write is proposed.
func TestTelemetryBeforeTheSchema(t *testing.T) {
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
	if _, err := p.DownTo(ctx, telemetrySchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	var proposed []string
	s, err = Open(ctx, path, WithoutUpgrade(), WithApplier(func(s *Store) Applier {
		return ApplierFunc(func(ctx context.Context, cmd Command) (Result, error) {
			proposed = append(proposed, cmd.Op())
			return s.ApplyLocal(ctx, cmd)
		})
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if got, err := s.Telemetry().Get(ctx); err != nil || got.Answered {
		t.Errorf("Get before the schema = %+v, %v; want unanswered", got, err)
	}
	if err := s.Telemetry().Set(ctx, true, "id", time.Now()); !errors.Is(err, ErrSchemaTooOld) {
		t.Errorf("Set before the schema = %v, want ErrSchemaTooOld", err)
	}
	if err := s.Telemetry().MarkSent(ctx, "id", time.Now()); !errors.Is(err, ErrSchemaTooOld) {
		t.Errorf("MarkSent before the schema = %v, want ErrSchemaTooOld", err)
	}
	if len(proposed) != 0 {
		t.Errorf("proposed %v before the schema, want nothing", proposed)
	}
	// A command that arrives anyway, from a newer leader's log, is refused.
	for _, cmd := range []Command{SetTelemetry{Enabled: true, InstallID: "id", At: 1}, MarkTelemetrySent{InstallID: "id", At: 2}} {
		if _, err := s.ApplyLocal(ctx, cmd); !errors.Is(err, ErrSchemaTooOld) {
			t.Errorf("ApplyLocal(%s) before the schema = %v, want ErrSchemaTooOld", cmd.Op(), err)
		}
	}
}
