// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestMergeHubs(t *testing.T) {
	tests := []struct {
		name  string
		lists [][]string
		want  []string
	}{
		{"empty", nil, nil},
		{"order kept, duplicates dropped", [][]string{{"https://a:7443", "https://b:7443"}, {"https://b:7443", "https://a:7443", "https://c:7443"}}, []string{"https://a:7443", "https://b:7443", "https://c:7443"}},
		{"invalid dropped", [][]string{{"", "http://a:7443", "https://", "not a url", " https://b:7443 "}}, []string{"https://b:7443"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergeHubs(tt.lists...); !slices.Equal(got, tt.want) {
				t.Errorf("mergeHubs = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHubsFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if got, err := readHubs(dir); err != nil || got != nil {
		t.Fatalf("readHubs without a file = %v, %v; want nil, nil", got, err)
	}
	want := []string{"https://a:7443", "https://b:7443"}
	if err := writeHubs(dir, want); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, HubsFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
	if got, err := readHubs(dir); err != nil || !slices.Equal(got, want) {
		t.Errorf("readHubs = %v, %v; want %v", got, err, want)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Errorf("data dir holds %v (err %v), want only %s", entries, err, HubsFile)
	}
	// A corrupted line is skipped, not fatal.
	if err := os.WriteFile(filepath.Join(dir, HubsFile), []byte("garbage\nhttps://c:7443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readHubs(dir); err != nil || !slices.Equal(got, []string{"https://c:7443"}) {
		t.Errorf("readHubs = %v, %v; want [https://c:7443]", got, err)
	}
}
