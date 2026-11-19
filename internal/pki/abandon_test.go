// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A Finish that failed between its two renames completes when called again,
// without a restart.
func TestCAFinishRetry(t *testing.T) {
	ca, dir := newCA(t)
	next, err := ca.GenerateNext(now)
	if err != nil {
		t.Fatal(err)
	}
	// The first rename happened; the second did not.
	if err := os.Rename(filepath.Join(dir, NextCACertFile), filepath.Join(dir, CACertFile)); err != nil {
		t.Fatal(err)
	}
	if err := ca.Finish(); err != nil {
		t.Fatalf("Finish after a half-done Finish: %v", err)
	}
	if _, err := ca.KeyDER(); !ca.Cert().Equal(next) || ca.Next() != nil || err != nil {
		t.Fatalf("the retried Finish did not leave the next CA as the only one, with its key: %v", err)
	}
	loaded, err := LoadOrCreateCA(dir, now)
	if err != nil || !loaded.Cert().Equal(next) {
		t.Fatalf("reload after the retried Finish: %v", err)
	}
	// A target that is not the next CA's is not taken for a done rename.
	other, otherDir := newCA(t)
	if _, err := other.GenerateNext(now); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(otherDir, NextCACertFile)); err != nil {
		t.Fatal(err)
	}
	if err := other.Finish(); err == nil {
		t.Fatal("Finish without the next CA certificate anywhere succeeded")
	}
}

// Abandon leaves the new CA as the only one, without any key on disk, and
// the data dir no longer loads.
func TestCAAbandon(t *testing.T) {
	ca, dir := newCA(t)
	newer, _ := newCA(t)
	if _, err := ca.GenerateNext(now); err != nil {
		t.Fatal(err)
	}
	oldClient := clientCert(t, ca, "pi")
	if err := ca.Abandon(newer.Cert()); err != nil {
		t.Fatal(err)
	}
	if !ca.Cert().Equal(newer.Cert()) || ca.Next() != nil || ca.IssuerOf(oldClient) != nil {
		t.Error("the old CA is still trusted after Abandon")
	}
	if _, err := ca.KeyDER(); err == nil {
		t.Error("an abandoned CA still has a key")
	}
	for _, f := range []string{CAKeyFile, NextCAKeyFile, NextCACertFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left behind: %v", f, err)
		}
	}
	if _, err := LoadOrCreateCA(dir, now); err == nil {
		t.Error("an abandoned data dir loads")
	}
}
