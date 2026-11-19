// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
)

// A standalone hub restored from a backup taken during a cluster's hub CA
// rotation drops the next CA and keeps serving, and trusting, its CA alone.
func TestLoadStandaloneCADropsTheNextCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.LoadOrCreateCA(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cur := ca.Cert()
	if _, err := ca.GenerateNext(time.Now()); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadStandaloneCA(dir, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Next() != nil || !loaded.Cert().Equal(cur) || len(loaded.TrustedCerts()) != 1 {
		t.Error("the standalone hub kept the next CA")
	}
	for _, f := range []string{pki.NextCACertFile, pki.NextCAKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, pki.CAKeyFile)); err != nil {
		t.Errorf("the CA key is gone: %v", err)
	}
}
