// SPDX-License-Identifier: AGPL-3.0-only

package hubconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gvart/hearth/internal/store"
)

func TestCheckName(t *testing.T) {
	for _, tc := range []struct {
		kind, name string
		ok         bool
	}{
		{store.ConfigPolicy, "policy.yaml", true},
		{store.ConfigPolicy, "other.yaml", false},
		{store.ConfigNotify, "notify.yaml", true},
		{store.ConfigAutomation, "backup.yaml", true},
		{store.ConfigRunbook, "r.yml", true},
		{store.ConfigAutomation, "../escape.yaml", false},
		{store.ConfigAutomation, "a/b.yaml", false},
		{store.ConfigAutomation, ".hidden.yaml", false},
		{store.ConfigAutomation, "notes.txt", false},
		{"secrets", "x.yaml", false},
	} {
		if err := CheckName(tc.kind, tc.name); (err == nil) != tc.ok {
			t.Errorf("CheckName(%s, %q) = %v, want ok %v", tc.kind, tc.name, err, tc.ok)
		}
	}
}

func TestWriteDirRefusesPaths(t *testing.T) {
	dir := t.TempDir()
	err := WriteDir(dir, []Doc{{Kind: store.ConfigAutomation, Name: "../../x.yaml", Content: []byte("x")}})
	if err == nil {
		t.Fatal("wrote a document named with a path")
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "..", "x.yaml")); err == nil {
		t.Fatal("a file escaped the export directory")
	}
}

func TestReadPathKinds(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) string {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write(PolicyFile, "classes: {}\n")
	auto := write("automations/a.yaml", "id: a\n")
	other := write("misc/p.yaml", "classes: {}\n")
	write("runbooks/.hidden.yaml", "skip\n")
	docs, err := ReadPath(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 || docs[0].ID() != "automation/a.yaml" || docs[1].ID() != "policy/policy.yaml" {
		t.Fatalf("dir docs = %+v", docs)
	}
	if docs, err := ReadPath(auto, ""); err != nil || docs[0].Kind != store.ConfigAutomation {
		t.Fatalf("automation file = %+v, %v", docs, err)
	}
	if _, err := ReadPath(other, ""); err == nil {
		t.Fatal("a file of unknown kind was read")
	}
	if docs, err := ReadPath(other, store.ConfigPolicy); err != nil || docs[0].Name != PolicyFile {
		t.Fatalf("--kind policy = %+v, %v", docs, err)
	}
}
