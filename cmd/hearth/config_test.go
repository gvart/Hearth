// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/hubconfig"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

// configHub is a standalone hub's data dir, store and configuration, as the
// hub runs them after its first start.
type configHub struct {
	dir     string
	st      *store.Store
	w       *hubconfig.Watcher
	pol     *policy.Engine
	n       *notify.Notifier
	logs    *bytes.Buffer
	fpStart string
}

// startConfigHub starts a hub's configuration on a new data dir holding
// files, by path relative to it.
func startConfigHub(t *testing.T, files map[string]string) *configHub {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, path, content)
	}
	storetest.Migrated(t, filepath.Join(dir, dbFile))
	st, err := store.Open(t.Context(), filepath.Join(dir, dbFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := pki.LoadOrCreateCA(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	sealer, err := cliNotifySealer(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := &configHub{dir: dir, st: st, pol: policy.NewWithConfig(st.Audit(), nil, policy.Config{}), n: &notify.Notifier{}, logs: &bytes.Buffer{}}
	log := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	opts := hubOptions{dataDir: dir}
	h.w = hubconfig.NewWatcher(hubconfig.WatcherConfig{
		Store: st.ConfigDocs(), Sealer: sealer, Policy: h.pol, Notifier: h.n, Actor: "hub-a", Log: log,
		Files: hubconfig.Files{
			Policy: filepath.Join(dir, policy.ConfigFile), Notify: notifyConfigPath(opts),
			AutomationsDir: filepath.Join(dir, "automations"), RunbooksDir: runbooksDirOf(opts),
		},
	})
	if _, err := applyHubConfig(t.Context(), opts, st, true, h.w, h.pol, h.n, log); err != nil {
		t.Fatal(err)
	}
	h.fpStart = h.fingerprint(t)
	return h
}

func (h *configHub) fingerprint(t *testing.T) string {
	t.Helper()
	fp, err := h.st.ConfigDocs().Fingerprint(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

// sync applies the store's documents, as the running hub does every 2 s.
func (h *configHub) sync(t *testing.T) {
	t.Helper()
	if _, err := h.w.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func (h *configHub) auditCount(t *testing.T, action policy.Action, decision string) int {
	t.Helper()
	entries, err := h.st.Audit().List(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.Action == string(action) && e.Decision == decision {
			n++
		}
	}
	return n
}

func importPath(t *testing.T, h *configHub, files map[string]string) (string, error) {
	t.Helper()
	src := t.TempDir()
	for name, content := range files {
		path := filepath.Join(src, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, path, content)
	}
	var out bytes.Buffer
	err := runConfigImport(t.Context(), h.dir, src, "", false, &out)
	return out.String(), err
}

var shell = policy.Request{ActorKind: policy.ActorWeb, ActorID: "laptop", Action: policy.DeviceShell}

// A denied action becomes allowed only once a policy import is applied, and
// the import is audited.
func TestConfigImportReloadsPolicy(t *testing.T) {
	h := startConfigHub(t, map[string]string{policy.ConfigFile: "actors:\n  web:\n    dangerous: deny\n"})
	if d, _ := h.pol.Check(shell); d != policy.Deny {
		t.Fatalf("before the import: %s, want deny", d)
	}
	if _, err := importPath(t, h, map[string]string{policy.ConfigFile: "classes:\n  dangerous: allow\n"}); err != nil {
		t.Fatal(err)
	}
	if d, _ := h.pol.Check(shell); d != policy.Deny {
		t.Fatalf("before the hub applied the import: %s, want deny", d)
	}
	h.sync(t)
	if d, _ := h.pol.Check(shell); d != policy.Allow {
		t.Fatalf("after the import: %s, want allow", d)
	}
	if h.auditCount(t, policy.ConfigImport, policy.Allow) == 0 {
		t.Error("the import is not audited")
	}
}

// Nothing invalid is written: not an invalid policy, not a policy whose
// approval channel is not a channel, not an automation that does not load,
// not a policy that locks the operator out of imports.
func TestConfigImportRejectsInvalid(t *testing.T) {
	h := startConfigHub(t, map[string]string{"notify.yaml": phoneChannel})
	for name, files := range map[string]map[string]string{
		"invalid policy":    {policy.ConfigFile: "classes:\n  dangerous: maybe\n"},
		"unknown field":     {policy.ConfigFile: "clases: {}\n"},
		"unknown channel":   {policy.ConfigFile: "approval_notify:\n  channel: pager\n"},
		"bad automation":    {"automations/a.yaml": "id: a\ntriggers: []\n"},
		"automation notify": {"automations/a.yaml": "id: a\ntriggers:\n  - type: manual\nactions:\n  - type: notify\n    channel: pager\n    message: hi\n"},
		"locks out import":  {policy.ConfigFile: "actors:\n  admin:\n    dangerous: deny\n"},
		"bad notify":        {"notify.yaml": "channels:\n  phone:\n    type: smoke\n"},
		"half invalid": {
			policy.ConfigFile: "classes:\n  dangerous: allow\n", "runbooks/r.yaml": "not: a runbook\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := importPath(t, h, files); err == nil {
				t.Fatal("imported")
			}
			if h.fingerprint(t) != h.fpStart {
				t.Fatal("something was written")
			}
		})
	}
}

// config.import is dangerous: a policy that denies dangerous actions to the
// operator refuses it, audited, and writes nothing.
func TestConfigImportDeniedByPolicy(t *testing.T) {
	h := startConfigHub(t, nil)
	// Such a policy cannot be imported (it locks the import out); a hub of an
	// older layout may still hold one.
	if err := h.st.ConfigDocs().Put(t.Context(), "test", []store.ConfigDoc{{
		Kind: store.ConfigPolicy, Name: policy.ConfigFile, Content: []byte("actors:\n  admin:\n    dangerous: deny\n"),
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	fp := h.fingerprint(t)
	_, err := importPath(t, h, map[string]string{"automations/a.yaml": "id: a\ntriggers:\n  - type: manual\nactions:\n  - type: log\n    message: hi\n"})
	if !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("import = %v, want ErrDenied", err)
	}
	if h.fingerprint(t) != fp {
		t.Fatal("a denied import wrote")
	}
	if h.auditCount(t, policy.ConfigImport, policy.Deny) == 0 {
		t.Error("the denial is not audited")
	}
	var out bytes.Buffer
	if err := runConfigDelete(t.Context(), h.dir, store.ConfigAutomation, "x.yaml", &out); err == nil {
		t.Error("delete of a missing document worked")
	}
}

// notify.yaml is sealed in the store and never in the logs or the audit log;
// export gives it back, and every other document byte for byte.
func TestConfigNotifySealedAndExport(t *testing.T) {
	const token = "tk_sentinel5ecret0123456789" //nolint:gosec // a test sentinel, not a credential
	notifyFile := phoneChannel + "    token: " + token + "\n"
	h := startConfigHub(t, nil)
	files := map[string]string{
		"notify.yaml":        notifyFile,
		policy.ConfigFile:    "# approvals go to the phone\napproval_notify:\n  channel: phone\n",
		"automations/a.yaml": "id: a   # odd spacing kept\ntriggers:\n  - type: manual\nactions:\n  - type: notify\n    channel: phone\n    message: hi\n",
		"runbooks/r.yml":     "id: r\nsteps:\n  - id: s\n    type: prompt\n    prompt: confirm\n    message: do it?\n",
	}
	out, err := importPath(t, h, files)
	if err != nil {
		t.Fatal(err)
	}
	h.sync(t)
	if !h.n.Has("phone") || h.pol.Config().ApprovalNotify.Channel != "phone" {
		t.Fatalf("not applied: %v %+v", h.n.Channels(), h.pol.Config())
	}

	stored, err := h.st.ConfigDocs().Get(t.Context(), store.ConfigNotify, "notify.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored.Content, []byte(token)) {
		t.Error("notify.yaml is stored in clear")
	}
	entries, err := h.st.Audit().List(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(string(e.Detail), token) {
			t.Errorf("audit entry %s holds the token", e.Action)
		}
	}
	if err := h.st.Close(); err != nil { // checkpoints the WAL into the file
		t.Fatal(err)
	}
	for _, f := range []string{dbFile, dbFile + "-wal"} {
		b, _ := os.ReadFile(filepath.Join(h.dir, f))
		if bytes.Contains(b, []byte(token)) {
			t.Errorf("%s holds the token", f)
		}
	}
	for _, leak := range []string{h.logs.String(), out} {
		if strings.Contains(leak, token) {
			t.Errorf("output holds the token: %s", leak)
		}
	}

	dst := filepath.Join(t.TempDir(), "export")
	var exp bytes.Buffer
	if err := runConfigExport(t.Context(), h.dir, dst, &exp); err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		path := filepath.Join(dst, name)
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Errorf("export %s = %q, %v; want %q", name, got, err, want)
		}
		if info, err := os.Stat(path); err == nil && info.Mode().Perm() != 0o600 {
			t.Errorf("export %s mode %v, want 0600", name, info.Mode().Perm())
		}
	}
	if strings.Contains(exp.String(), token) {
		t.Error("export output holds the token")
	}
}

// An edit made on one hub's store, merged into another's, is applied there.
func TestConfigMergedEditApplied(t *testing.T) {
	var muts []store.Mutation
	a := storetest.Open(t, store.WithApplier(func(s *store.Store) store.Applier {
		return store.ApplierFunc(func(ctx context.Context, cmd store.Command) (store.Result, error) {
			res, m, err := s.ApplyLocalMutations(ctx, cmd)
			muts = append(muts, m...)
			return res, err
		})
	}))
	h := startConfigHub(t, map[string]string{policy.ConfigFile: "actors:\n  web:\n    dangerous: deny\n"})
	if err := a.ConfigDocs().Put(t.Context(), "admin/op", []store.ConfigDoc{{
		Kind: store.ConfigPolicy, Name: policy.ConfigFile, Content: []byte("classes:\n  dangerous: allow\n"),
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := h.st.Merge(t.Context(), muts); err != nil {
		t.Fatal(err)
	}
	h.sync(t)
	if d, _ := h.pol.Check(shell); d != policy.Allow {
		t.Fatalf("merged policy not applied: %s", d)
	}
}
