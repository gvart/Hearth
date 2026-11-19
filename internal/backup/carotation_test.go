// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// A backup taken during a hub CA rotation holds both CAs (the next CA's key
// only with --backup-include-ca); one taken after the finish holds only the
// new CA.
func TestBackupDuringCARotation(t *testing.T) {
	dir, st := newHub(t)
	ca, err := pki.LoadOrCreateCA(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	next, err := ca.GenerateNext(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.TrustNext(next); err != nil { // the rotation under way, as a cluster hub learns
		t.Fatal(err)
	}
	restore := func(t *testing.T, withoutKey bool) string {
		t.Helper()
		opts := createOpts(dir, st, filepath.Join(t.TempDir(), "hub.hbk"))
		opts.WithoutCAKey = withoutKey
		if _, err := Create(t.Context(), opts); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "restored")
		if _, err := Restore(t.Context(), RestoreOptions{Input: opts.Output, Passphrase: testPassphrase, DataDir: target}); err != nil {
			t.Fatal(err)
		}
		return target
	}
	exists := func(path string) bool {
		_, err := os.Stat(path)
		return !errors.Is(err, fs.ErrNotExist)
	}

	t.Run("with the CA key", func(t *testing.T) {
		target := restore(t, false)
		restored, err := pki.LoadOrCreateCA(target, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if !restored.Cert().Equal(ca.Cert()) || restored.Next() == nil || !restored.Next().Equal(next) || !restored.HasNextKey() {
			t.Error("the restored hub does not hold both CAs with their keys")
		}
		if fi, err := os.Stat(filepath.Join(target, pki.NextCAKeyFile)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("restored next CA key: %v, %v; want mode 0600", fi, err)
		}
	})
	t.Run("without the CA key", func(t *testing.T) {
		target := restore(t, true)
		if !exists(filepath.Join(target, pki.NextCACertFile)) {
			t.Error("the next CA certificate is not in the backup")
		}
		for _, f := range []string{pki.CAKeyFile, pki.NextCAKeyFile} {
			if exists(filepath.Join(target, f)) {
				t.Errorf("%s is in a backup without the CA key", f)
			}
		}
	})
	t.Run("after the finish", func(t *testing.T) {
		if err := ca.Finish(); err != nil {
			t.Fatal(err)
		}
		target := restore(t, false)
		for _, f := range []string{pki.NextCACertFile, pki.NextCAKeyFile} {
			if exists(filepath.Join(target, f)) {
				t.Errorf("%s is in a backup taken after the finish", f)
			}
		}
		b, err := os.ReadFile(filepath.Join(target, pki.CACertFile))
		if err != nil || !bytes.Equal(b, pki.EncodeCertPEM(next)) {
			t.Errorf("restored CA certificate is not the new CA: %v", err)
		}
	})
}

func TestRestoreRefusesBadNextCA(t *testing.T) {
	files, snapshot := hubParts(t)
	nextDir := t.TempDir()
	if _, err := pki.LoadOrCreateCA(nextDir, time.Now()); err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(nextDir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	nextCert := namedFile{pki.NextCACertFile, read(pki.CACertFile)}
	nextKey := namedFile{pki.NextCAKeyFile, read(pki.CAKeyFile)}
	m := Manifest{Format: formatVersion, Schema: store.SchemaVersion()}
	tests := map[string]struct {
		m       Manifest
		entries []namedFile
	}{
		"next key without its certificate": {m, append(append([]namedFile{}, files...), nextKey)},
		"next key of another CA":           {m, append(append([]namedFile{}, files...), nextCert, namedFile{pki.NextCAKeyFile, otherCAKey(t)})},
		"next key without the CA key":      {Manifest{Format: formatVersion, Schema: store.SchemaVersion(), NoCAKey: true}, []namedFile{files[0], nextCert, nextKey}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			input := craftBackup(t, tt.m, tt.entries, snapshot)
			target := filepath.Join(t.TempDir(), "restored")
			if _, err := Restore(t.Context(), RestoreOptions{Input: input, Passphrase: testPassphrase, DataDir: target}); err == nil {
				t.Fatal("Restore accepted the backup")
			}
		})
	}
	// Its certificate with its key is fine.
	input := craftBackup(t, m, append(append([]namedFile{}, files...), nextCert, nextKey), snapshot)
	if _, err := Restore(t.Context(), RestoreOptions{Input: input, Passphrase: testPassphrase, DataDir: filepath.Join(t.TempDir(), "r")}); err != nil {
		t.Fatalf("Restore with a matching next CA: %v", err)
	}
}
