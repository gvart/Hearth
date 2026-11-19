// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func TestBackupWithoutCAKey(t *testing.T) {
	dir, st := newHub(t)
	file := filepath.Join(t.TempDir(), "nokey.hbk")
	m, err := Create(t.Context(), CreateOptions{
		DataDir: dir, Store: st, Output: file, Passphrase: testPassphrase, WithoutCAKey: true, kdf: testKDF,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !m.NoCAKey {
		t.Fatal("manifest does not say the CA key is out")
	}
	target := filepath.Join(t.TempDir(), "restored")
	rm, err := Restore(t.Context(), RestoreOptions{Input: file, Passphrase: testPassphrase, DataDir: target})
	if err != nil {
		t.Fatalf("restore a backup without the CA key: %v", err)
	}
	if !rm.NoCAKey {
		t.Fatal("restored manifest does not say the CA key is out")
	}
	if _, err := os.Stat(filepath.Join(target, pki.CAKeyFile)); !os.IsNotExist(err) {
		t.Fatalf("ca.key restored from a backup without it: %v", err)
	}
	for _, name := range []string{pki.CACertFile, dbName, notifyName, policy.ConfigFile, completeMarker} {
		if _, err := os.Stat(filepath.Join(target, name)); err != nil {
			t.Errorf("%s not restored: %v", name, err)
		}
	}
}

// TestRestoreRefusesCAKeyMismatch: the manifest and the entries must agree on
// whether the CA key is in.
func TestRestoreRefusesCAKeyMismatch(t *testing.T) {
	dir, st := newHub(t)
	snapshot := filepath.Join(t.TempDir(), dbName)
	if err := st.VacuumInto(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	schema, err := st.SchemaVersion(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		noCAKey      bool
		withoutKey   bool
		wantRestored bool
	}{
		{"key in, manifest says out", true, false, false},
		{"key out, manifest says in", false, true, false},
		{"key in", false, false, true},
		{"key out", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, err := configFiles(CreateOptions{DataDir: dir, WithoutCAKey: tc.withoutKey})
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			m := Manifest{Format: formatVersion, CreatedAt: time.Now().UTC(), Schema: schema, NoCAKey: tc.noCAKey}
			if err := writeArchive(t.Context(), &buf, testPassphrase, testKDF, m, files, snapshot); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "b.hbk")
			if err := os.WriteFile(file, buf.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "restored")
			_, err = Restore(t.Context(), RestoreOptions{Input: file, Passphrase: testPassphrase, DataDir: target})
			if tc.wantRestored {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("restore = %v, want ErrCorrupt", err)
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatalf("a refused restore left the data dir: %v", err)
			}
		})
	}
}

func TestScheduledBackupCAKey(t *testing.T) {
	for _, include := range []bool{false, true} {
		t.Run(map[bool]string{false: "left out", true: "included"}[include], func(t *testing.T) {
			b := newMemBucket()
			s, _, st := newScheduler(t, b, nil, time.Now())
			s.cfg.Backup.WithoutCAKey = !include
			if err := s.RunOnce(t.Context()); err != nil {
				t.Fatal(err)
			}
			entries, err := st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.HubScheduledBackup)}}, 10)
			if err != nil || len(entries) != 1 {
				t.Fatalf("audit = %+v, %v", entries, err)
			}
			want := `"ca_key":false`
			if include {
				want = `"ca_key":true`
			}
			if !strings.Contains(string(entries[0].Detail), want) {
				t.Fatalf("audit detail %s, want %s", entries[0].Detail, want)
			}
			keys := b.keys()
			file := filepath.Join(t.TempDir(), "dl.hbk")
			if err := os.WriteFile(file, b.objects[keys[0]], 0o600); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "restored")
			m, err := Restore(t.Context(), RestoreOptions{Input: file, Passphrase: testPassphrase, DataDir: target})
			if err != nil {
				t.Fatal(err)
			}
			_, statErr := os.Stat(filepath.Join(target, pki.CAKeyFile))
			if m.NoCAKey == include || (statErr == nil) != include {
				t.Fatalf("include %v: manifest NoCAKey %v, ca.key %v", include, m.NoCAKey, statErr)
			}
		})
	}
}
