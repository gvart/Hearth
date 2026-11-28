// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
)

// writeTestIndex writes an index of lamp at versions into dir, each with a
// module of its own, and returns the index's path.
func writeTestIndex(t *testing.T, dir string, versions ...string) string {
	t.Helper()
	idx := plugins.Index{Format: plugins.IndexFormat}
	for _, v := range versions {
		b := []byte("\x00asm\x01\x00\x00\x00" + v)
		file := "lamp-" + v + ".wasm"
		if err := os.WriteFile(filepath.Join(dir, file), b, 0o600); err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		idx.Plugins = append(idx.Plugins, plugins.IndexEntry{
			Name: "lamp", Version: v, Description: "A lamp over HTTP", Runtime: plugins.RuntimeWasm, URL: file,
			SHA256: hex.EncodeToString(s[:]), Capabilities: []string{plugins.CapCommand},
			Commands: []plugins.CommandSpec{{Name: "turn_on", Class: policy.Safe}},
			Host:     plugins.HostGrants{HTTP: &plugins.HTTPGrant{Allow: []string{"192.0.2.9:80"}}},
		})
	}
	b, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "index.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPluginRegistryCommands(t *testing.T) {
	dataDir, _ := initHub(t)
	pub := t.TempDir()
	keyFile := filepath.Join(t.TempDir(), "signing.key")

	out, err := execute(t, "plugin", "index", "keygen", "--key-file", keyFile)
	if err != nil {
		t.Fatalf("keygen = %v\n%s", err, out)
	}
	key := regexp.MustCompile(`--plugin-index-key\): (\S+)`).FindStringSubmatch(out)
	if key == nil {
		t.Fatalf("keygen printed no public key:\n%s", out)
	}
	seed, _ := os.ReadFile(keyFile)
	if strings.Contains(out, strings.TrimSpace(string(seed))) {
		t.Fatal("keygen printed the signing key")
	}
	if fi, err := os.Stat(keyFile); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file %v %v", fi, err)
	}
	if _, err := execute(t, "plugin", "index", "keygen", "--key-file", keyFile); err == nil {
		t.Fatal("keygen overwrote a key")
	}

	index := writeTestIndex(t, pub, "1.0.0")
	sign := func() {
		t.Helper()
		if out, err := execute(t, "plugin", "index", "sign", index, "--key-file", keyFile); err != nil || strings.Contains(out, strings.TrimSpace(string(seed))) {
			t.Fatalf("sign = %v\n%s", err, out)
		}
	}
	sign()
	if out, err := execute(t, "plugin", "index", "verify", index, "--key", key[1]); err != nil || !strings.Contains(out, "verifies") {
		t.Fatalf("verify = %v\n%s", err, out)
	}
	other := writeTestIndex(t, t.TempDir(), "1.0.0")
	if _, err := execute(t, "plugin", "index", "verify", other, "--key", key[1]); err == nil {
		t.Fatal("an unsigned index verified")
	}

	regFlags := []string{"--data-dir", dataDir, "--plugin-index", index, "--plugin-index-key", key[1]}
	if out, err := execute(t, append([]string{"plugin", "search", "lamp"}, regFlags[2:]...)...); err != nil || !strings.Contains(out, "192.0.2.9:80") {
		t.Fatalf("search = %v\n%s", err, out)
	}
	if _, err := execute(t, "plugin", "install", "lamp", "--yes", "--data-dir", dataDir); err == nil || !strings.Contains(err.Error(), "no plugin index") {
		t.Fatalf("install without an index = %v", err)
	}

	// Declined: nothing installed.
	cmd := newRootCmd(buildInfo{Version: "dev"})
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetIn(strings.NewReader("n\n"))
	cmd.SetArgs(append([]string{"plugin", "install", "lamp"}, regFlags...))
	if err := cmd.ExecuteContext(t.Context()); err != nil || !strings.Contains(buf.String(), "Nothing was changed") ||
		!strings.Contains(buf.String(), "HTTP access") || !strings.Contains(buf.String(), "turn_on:safe") {
		t.Fatalf("declined install = %v\n%s", err, buf.String())
	}
	st := plugins.NewInstalledStore(dataDir)
	if l, _ := st.List(); len(l) != 0 {
		t.Fatalf("a declined install installed %+v", l)
	}

	if out, err := execute(t, append([]string{"plugin", "install", "lamp", "--yes"}, regFlags...)...); err != nil || !strings.Contains(out, "Installed lamp 1.0.0") {
		t.Fatalf("install = %v\n%s", err, out)
	}
	if out, err := execute(t, append([]string{"plugin", "update", "lamp", "--yes"}, regFlags...)...); err == nil {
		t.Fatalf("update to the version installed = %s", out)
	}

	writeTestIndex(t, pub, "0.9.0", "1.0.0", "1.2.0")
	// Not signed again: refused.
	if _, err := execute(t, append([]string{"plugin", "update", "lamp", "--yes"}, regFlags...)...); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("update from a tampered index = %v", err)
	}
	sign()
	if out, err := execute(t, append([]string{"plugin", "list"}, regFlags...)...); err != nil || !strings.Contains(out, "lamp") || !strings.Contains(out, "1.2.0") {
		t.Fatalf("list = %v\n%s", err, out)
	}
	if out, err := execute(t, append([]string{"plugin", "update", "lamp", "--yes"}, regFlags...)...); err != nil || !strings.Contains(out, "Update 1.0.0 to lamp 1.2.0") {
		t.Fatalf("update = %v\n%s", err, out)
	}
	if _, err := execute(t, append([]string{"plugin", "update", "lamp", "--yes", "--version", "0.9.0"}, regFlags...)...); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("downgrade = %v", err)
	}
	if out, err := execute(t, append([]string{"plugin", "update", "lamp", "--yes", "--version", "0.9.0", "--allow-downgrade"}, regFlags...)...); err != nil {
		t.Fatalf("explicit downgrade = %v\n%s", err, out)
	}
	if in, _, _ := st.Get("lamp"); in.Entry.Version != "0.9.0" {
		t.Fatalf("installed %+v", in.Entry)
	}

	// A module that is not the one pinned is refused.
	if err := os.WriteFile(filepath.Join(pub, "lamp-1.2.0.wasm"), []byte("evil"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := execute(t, append([]string{"plugin", "update", "lamp", "--yes"}, regFlags...)...); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("tampered module = %v", err)
	}

	if out, err := execute(t, "plugin", "remove", "lamp", "--data-dir", dataDir); err != nil {
		t.Fatalf("remove = %v\n%s", err, out)
	}
	if _, err := execute(t, "plugin", "remove", "lamp", "--data-dir", dataDir); err == nil {
		t.Fatal("removed twice")
	}

	all, err := openStore(t, dataDir).Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, e := range all {
		if e.Decision == policy.Allow {
			count[e.Action]++
		}
	}
	if count[string(policy.PluginRegistryInstall)] != 1 || count[string(policy.PluginRegistryUpdate)] != 2 || count[string(policy.PluginRegistryRemove)] != 1 {
		t.Fatalf("audit counts %v", count)
	}
}

func TestPluginIndexSignNeedsAKey(t *testing.T) {
	index := writeTestIndex(t, t.TempDir(), "1.0.0")
	t.Setenv(signingKeyEnv, "")
	if _, err := execute(t, "plugin", "index", "sign", index); err == nil || !strings.Contains(err.Error(), "no signing key") {
		t.Fatalf("sign without a key = %v", err)
	}
	t.Setenv(signingKeyEnv, "c2VjcmV0LXNlZWQ=")
	_, err := execute(t, "plugin", "index", "sign", index)
	if err == nil || strings.Contains(err.Error(), "c2VjcmV0LXNlZWQ=") {
		t.Fatalf("sign with a bad key = %v", err)
	}
}
