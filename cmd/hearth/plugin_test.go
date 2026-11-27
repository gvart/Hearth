// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/policy"
)

func TestPluginCommands(t *testing.T) {
	dir, _ := initHub(t)
	src := t.TempDir()
	prog, manifest := filepath.Join(src, "lamp"), filepath.Join(src, "plugin.yaml")
	if err := os.WriteFile(prog, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("protocol: 1\nname: go-lamp\nversion: 0.1.0\ncapabilities: [command]\ncommands:\n  - name: turn_on\n    class: safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	blobs := func() []os.DirEntry {
		entries, _ := os.ReadDir(filepath.Join(dir, hub.PluginBlobsDir))
		return entries
	}
	upload := []string{"plugin", "upload", prog, "--manifest", manifest, "--os", "linux", "--arch", "arm64", "--data-dir", dir}
	if out, err := execute(t, append(upload, "--dry-run")...); err != nil || !strings.Contains(out, "Dry run") {
		t.Fatalf("dry run = %v\n%s", err, out)
	}
	if len(blobs()) != 0 {
		t.Fatalf("a dry run kept the program: %v", blobs())
	}
	out, err := execute(t, upload...)
	if err != nil || !strings.Contains(out, "Uploaded plugin go-lamp") {
		t.Fatalf("upload = %v\n%s", err, out)
	}
	for _, args := range [][]string{
		{prog, "--manifest", manifest, "--os", "../x"},
		{prog, "--manifest", prog},
		{filepath.Join(src, "missing"), "--manifest", manifest},
	} {
		if _, err := execute(t, append([]string{"plugin", "upload", "--data-dir", dir}, args...)...); err == nil {
			t.Errorf("upload %v succeeded", args)
		}
	}
	out, err = execute(t, "plugin", "list", "--data-dir", dir)
	if err != nil || !strings.Contains(out, "go-lamp/linux/arm64") || !strings.Contains(out, "turn_on:safe") {
		t.Fatalf("list = %v\n%s", err, out)
	}
	if out, err := execute(t, "plugin", "delete", "go-lamp/linux/arm64", "--data-dir", dir); err != nil {
		t.Fatalf("delete = %v\n%s", err, out)
	}
	if len(blobs()) != 0 {
		t.Errorf("delete kept the program: %v", blobs())
	}
	if _, err := execute(t, "plugin", "delete", "go-lamp/linux/arm64", "--data-dir", dir); err == nil {
		t.Error("deleted twice")
	}
	all, err := openStore(t, dir).Audit().List(t.Context(), 50)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range all {
		actions = append(actions, e.Action)
	}
	for _, a := range []policy.Action{policy.PluginBinaryUpload, policy.PluginBinaryDelete} {
		if !strings.Contains(strings.Join(actions, " "), string(a)) {
			t.Errorf("no %s in the audit log: %v", a, actions)
		}
	}
}
