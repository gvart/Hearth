// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/hubconfig"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

// startConfig runs applyHubConfig as a standalone hub starting on dataDir.
func startConfig(t *testing.T, st *store.Store, dataDir string) (*policy.Engine, *notify.Notifier, error) {
	t.Helper()
	sealer, err := kubernetes.NewPurposeSealer([]byte("test CA key"), notifySealInfo)
	if err != nil {
		t.Fatal(err)
	}
	opts := hubOptions{dataDir: dataDir}
	pol := policy.New(st.Audit())
	n := &notify.Notifier{}
	w := hubconfig.NewWatcher(hubconfig.WatcherConfig{
		Store: st.ConfigDocs(), Sealer: sealer, Policy: pol, Notifier: n, Actor: "hub-a",
		Files: hubconfig.Files{
			Policy: filepath.Join(dataDir, policy.ConfigFile), Notify: notifyConfigPath(opts),
			AutomationsDir: filepath.Join(dataDir, "automations"), RunbooksDir: runbooksDirOf(opts),
		},
	})
	if err := w.ImportFirst(t.Context()); err != nil {
		return nil, nil, err
	}
	_, err = applyHubConfig(t.Context(), opts, st, w, pol, n, slog.New(slog.DiscardHandler))
	return pol, n, err
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const phoneChannel = "channels:\n  phone:\n    type: ntfy\n    url: http://ntfy.lan\n    topic: lab\n"

// The approval channel must be one of the notification channels, whether
// the configuration comes from the files or the store.
func TestApplyHubConfigApprovalChannel(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "notify.yaml"), phoneChannel)
	writeFile(t, filepath.Join(dir, policy.ConfigFile), "approval_notify:\n  channel: pager\n")
	if _, _, err := startConfig(t, storetest.Open(t), dir); err == nil || !strings.Contains(err.Error(), `"pager"`) {
		t.Errorf("unknown channel = %v, want an error naming it", err)
	}
	writeFile(t, filepath.Join(dir, policy.ConfigFile), "approval_notify:\n  channel: phone\n")
	pol, n, err := startConfig(t, storetest.Open(t), dir)
	if err != nil {
		t.Fatal(err)
	}
	if pol.Config().ApprovalNotify.Channel != "phone" || !n.Has("phone") {
		t.Errorf("config = %+v, channels = %v", pol.Config(), n.Channels())
	}
}

// A hub imports its files into an empty store once, audited; after that
// the store is the configuration and the files are not read.
func TestApplyHubConfigImportsOnce(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, policy.ConfigFile), "classes:\n  dangerous: deny\n")
	st := storetest.Open(t)
	pol, _, err := startConfig(t, st, dir)
	if err != nil {
		t.Fatal(err)
	}
	if pol.Config().Classes[policy.Dangerous] != policy.ModeDeny {
		t.Fatalf("policy = %+v", pol.Config())
	}
	entries, err := st.Audit().List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	imports := 0
	for _, e := range entries {
		if e.Action == string(policy.ConfigImportFirst) {
			imports++
		}
	}
	if imports == 0 {
		t.Fatal("first import not audited")
	}
	// A restart with a changed file: the store wins, nothing is imported.
	writeFile(t, filepath.Join(dir, policy.ConfigFile), "classes:\n  dangerous: allow\n")
	pol, _, err = startConfig(t, st, dir)
	if err != nil {
		t.Fatal(err)
	}
	if pol.Config().Classes[policy.Dangerous] != policy.ModeDeny {
		t.Fatalf("the file was read again: policy = %+v", pol.Config())
	}
	entries, _ = st.Audit().List(ctx, 100)
	again := 0
	for _, e := range entries {
		if e.Action == string(policy.ConfigImportFirst) {
			again++
		}
	}
	if again != imports {
		t.Errorf("imported again: %d import entries, want %d", again, imports)
	}
}
