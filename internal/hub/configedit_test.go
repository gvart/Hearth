// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/backup"
	"github.com/gvart/hearth/internal/hubconfig"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

// testSealer stands in for the hub's notify sealer: what it seals does not
// hold the plaintext.
type testSealer struct{}

func (testSealer) Seal(id string, b []byte) ([]byte, error) {
	out := append([]byte("sealed:"+id+":"), b...)
	for i := len("sealed:" + id + ":"); i < len(out); i++ {
		out[i] ^= 0x5a
	}
	return out, nil
}

func (s testSealer) Open(id string, b []byte) ([]byte, error) {
	prefix := "sealed:" + id + ":"
	if !bytes.HasPrefix(b, []byte(prefix)) {
		return nil, errors.New("not sealed for " + id)
	}
	out := bytes.Clone(b[len(prefix):])
	for i := range out {
		out[i] ^= 0x5a
	}
	return out, nil
}

// testKinds are the step types `hearth config import` validates with.
func testKinds(n *notify.Notifier) automation.Kinds {
	kinds := automation.Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(kinds.Triggers, automation.Triggers(automation.TriggerDeps{}))
	maps.Copy(kinds.Actions, automation.Actions(automation.ActionDeps{Notifier: n}))
	return kinds
}

// withConfigDocs turns the editors of configuration documents on, with the
// automation documents of the store.
func withConfigDocs(c *Config) {
	c.ConfigSealer, c.ConfigKinds = testSealer{}, testKinds
	c.AutomationDocs = hubconfig.StoreDocs(c.Store.ConfigDocs(), store.ConfigAutomation, "", string(policy.AutomationApply), time.Now)
	c.AutomationKinds = testKinds(&notify.Notifier{})
}

func newConfigFixture(t *testing.T, cfg policy.Config) *apiFixture {
	t.Helper()
	f := newAPIFixture(t, true, withPolicy(cfg), withConfigDocs)
	// A first import, as a hub's start makes, so the store holds documents.
	if err := f.st.ConfigDocs().Put(t.Context(), "test", []store.ConfigDoc{
		{Kind: store.ConfigPolicy, Name: hubconfig.PolicyFile, Content: []byte{}},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return f
}

func docBodyJSON(yamlText, revision string) string {
	b, _ := json.Marshal(map[string]string{"yaml": yamlText, "revision": revision})
	return string(b)
}

func TestPolicyEditor(t *testing.T) {
	f := newConfigFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	got := decode[DocJSON](t, f.do(t, http.MethodGet, "/api/v1/policy", "", c))
	if got.YAML != "" || got.File != "policy.yaml" {
		t.Fatalf("policy = %+v", got)
	}
	const next = "classes:\n  dangerous: confirm\n"

	// A stale session is refused, audited, and nothing is written.
	stale := staleSession(t, f)
	if resp := f.do(t, http.MethodPut, "/api/v1/policy", docBodyJSON(next, got.Revision), stale); errorCode(t, resp) != "reauth_required" {
		t.Fatalf("save without re-auth = %d %s", resp.StatusCode, resp.body)
	}
	// Anyone signed in reads it.
	if resp := f.do(t, http.MethodGet, "/api/v1/policy", "", stale); resp.StatusCode != http.StatusOK {
		t.Fatalf("read with a stale session = %d", resp.StatusCode)
	}

	// Invalid, and locking the web UI out: refused with problems, unwritten.
	for _, bad := range []string{
		"classes:\n  dangerous: sometimes\n",
		"nonsense: true\n",
		"actors:\n  web:\n    dangerous: deny\n",
		"classes:\n  dangerous: deny\n",
	} {
		resp := f.do(t, http.MethodPut, "/api/v1/policy", docBodyJSON(bad, got.Revision), c)
		if resp.StatusCode != http.StatusUnprocessableEntity || len(decode[ProblemsJSON](t, resp).Problems) == 0 {
			t.Errorf("save %q = %d %s, want 422 with problems", bad, resp.StatusCode, resp.body)
		}
		v := decode[ValidationJSON](t, f.do(t, http.MethodPost, "/api/v1/policy/validate", docBodyJSON(bad, ""), c))
		if v.Valid {
			t.Errorf("validate %q = valid", bad)
		}
	}
	if v := decode[ValidationJSON](t, f.do(t, http.MethodPost, "/api/v1/policy/validate", docBodyJSON(next, ""), c)); !v.Valid {
		t.Errorf("validate a good policy = %+v", v)
	}

	resp := f.do(t, http.MethodPut, "/api/v1/policy", docBodyJSON(next, got.Revision), c)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save = %d %s", resp.StatusCode, resp.body)
	}
	saved := decode[DocJSON](t, resp)
	stored, err := f.st.ConfigDocs().Get(t.Context(), store.ConfigPolicy, hubconfig.PolicyFile)
	if err != nil || string(stored.Content) != next {
		t.Fatalf("stored policy = %q, %v", stored.Content, err)
	}
	// An edit from the old revision is a conflict.
	if resp := f.do(t, http.MethodPut, "/api/v1/policy", docBodyJSON("", got.Revision), c); resp.StatusCode != http.StatusConflict {
		t.Errorf("save from a stale revision = %d, want 409", resp.StatusCode)
	}
	if saved.Revision != automation.Revision([]byte(next)) {
		t.Errorf("revision = %s", saved.Revision)
	}
	imports := 0
	for _, e := range auditOf(t, f, policy.ConfigImport) {
		if e.ActorKind == policy.ActorWeb {
			imports++
		}
	}
	if imports < 2 {
		t.Errorf("audited %d web imports, want the refusal and the save", imports)
	}
}

// Policy decides on every write: a configuration that denies dangerous web
// actions refuses the editors.
func TestConfigEditorsFollowPolicy(t *testing.T) {
	f := newConfigFixture(t, policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
		policy.ActorWeb: {policy.Dangerous: policy.ModeDeny},
	}})
	c := sessionCookie(t, f.login(t, testPassword))
	for _, req := range []struct{ method, path, body string }{
		{http.MethodPut, "/api/v1/policy", docBodyJSON("", automation.Revision(nil))},
		{http.MethodPut, "/api/v1/notify/channels/phone", `{"type":"ntfy","url":"https://ntfy.sh","topic":"t"}`},
		{http.MethodPut, "/api/v1/runbook-files/rb.yaml", docBodyJSON(testRunbook, "")},
	} {
		if resp := f.do(t, req.method, req.path, req.body, c); resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "forbidden" {
			t.Errorf("%s %s = %d %s, want 403 forbidden", req.method, req.path, resp.StatusCode, resp.body)
		}
	}
}

// The CLI's import keeps its own lockout guard: a policy that denies only
// the web UI's dangerous actions is a hardening an operator on the hub host
// may choose. The editor refuses it.
func TestWebLockout(t *testing.T) {
	webDenied := []hubconfig.Doc{policyDoc("actors:\n  web:\n    dangerous: deny\n")}
	if err := hubconfig.CheckLockout(webDenied); err != nil {
		t.Errorf("CheckLockout refused a web-only denial: %v", err)
	}
	if err := hubconfig.CheckWebLockout(webDenied); err == nil || !strings.Contains(err.Error(), "web UI") {
		t.Errorf("CheckWebLockout = %v, want a refusal naming the web UI", err)
	}
	adminDenied := []hubconfig.Doc{policyDoc("actors:\n  admin:\n    dangerous: deny\n")}
	if hubconfig.CheckLockout(adminDenied) == nil || hubconfig.CheckWebLockout(adminDenied) == nil {
		t.Error("an admin lockout was accepted")
	}
	held := []hubconfig.Doc{policyDoc("classes:\n  dangerous: confirm\n")}
	if err := hubconfig.CheckWebLockout(held); err != nil {
		t.Errorf("holding dangerous actions was refused: %v", err)
	}
}

const (
	ntfyToken = "tk_secret_do_not_serve_1f2e"
	ntfyTopic = "secret-topic-4b5c"
	ntfyURL   = "https://ntfy.internal.example"
)

// A channel's fields are write-only: no answer, log or audit entry holds
// them, the stored document is sealed, an empty field keeps the stored value
// and clear empties it.
func TestNotifyEditorSecretsWriteOnly(t *testing.T) {
	f := newConfigFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	put := func(body string, cookie *http.Cookie) apiResp {
		return f.do(t, http.MethodPut, "/api/v1/notify/channels/phone", body, cookie)
	}
	full := `{"type":"ntfy","url":"` + ntfyURL + `","topic":"` + ntfyTopic + `","token":"` + ntfyToken + `"}`
	if resp := put(full, staleSession(t, f)); errorCode(t, resp) != "reauth_required" {
		t.Fatalf("save without re-auth = %d %s", resp.StatusCode, resp.body)
	}
	if resp := put(`{"type":"pager"}`, c); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown type = %d", resp.StatusCode)
	}
	if resp := put(`{"type":"ntfy","topic":"t"}`, c); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("a channel without its url = %d %s, want 422", resp.StatusCode, resp.body)
	}
	var answers []string
	resp := put(full, c)
	answers = append(answers, string(resp.body))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("save = %d %s", resp.StatusCode, resp.body)
	}
	cfg := f.do(t, http.MethodGet, "/api/v1/notify/config", "", c)
	answers = append(answers, string(cfg.body))
	chans := decode[struct {
		Channels []NotifyChannelJSON `json:"channels"`
	}](t, cfg).Channels
	if len(chans) != 1 || chans[0].Name != "phone" || chans[0].Type != "ntfy" ||
		!chans[0].Set["url"] || !chans[0].Set["topic"] || !chans[0].Set["token"] {
		t.Fatalf("channels = %+v", chans)
	}

	// Empty keeps; clear empties.
	resp = put(`{"type":"ntfy"}`, c)
	answers = append(answers, string(resp.body))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("save keeping the fields = %d %s", resp.StatusCode, resp.body)
	}
	file := storedNotify(t, f)
	if ch := file.Channels["phone"]; ch.Token != ntfyToken || ch.Topic != ntfyTopic || ch.URL != ntfyURL {
		t.Fatalf("an empty field did not keep the value: %+v", ch)
	}
	if resp := put(`{"type":"ntfy","clear":["token"]}`, c); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("clear = %d %s", resp.StatusCode, resp.body)
	}
	if ch := storedNotify(t, f).Channels["phone"]; ch.Token != "" || ch.Topic != ntfyTopic {
		t.Fatalf("clear token: %+v", ch)
	}
	if resp := put(`{"type":"ntfy","clear":["bot_token"]}`, c); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("clearing another type's field = %d", resp.StatusCode)
	}

	// A channel the policy's approvals use cannot be deleted.
	pol := "approval_notify:\n  channel: phone\n"
	cur := decode[DocJSON](t, f.do(t, http.MethodGet, "/api/v1/policy", "", c))
	if resp := f.do(t, http.MethodPut, "/api/v1/policy", docBodyJSON(pol, cur.Revision), c); resp.StatusCode != http.StatusOK {
		t.Fatalf("save policy = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodDelete, "/api/v1/notify/channels/phone", "", c); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("delete a channel in use = %d %s, want 422", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodDelete, "/api/v1/notify/channels/nope", "", c); resp.StatusCode != http.StatusNotFound {
		t.Errorf("delete an unknown channel = %d", resp.StatusCode)
	}

	// Nothing served, logged or audited holds a value.
	all, _ := f.st.Audit().List(t.Context(), 500)
	for _, secret := range []string{ntfyToken, ntfyTopic, ntfyURL} {
		for _, a := range answers {
			if strings.Contains(a, secret) {
				t.Errorf("an answer holds %q: %s", secret, a)
			}
		}
		if strings.Contains(f.logs.String(), secret) {
			t.Errorf("the logs hold %q", secret)
		}
		for _, e := range all {
			if strings.Contains(e.Result+e.Target+string(e.Detail), secret) {
				t.Errorf("audit entry holds %q: %+v", secret, e)
			}
		}
		stored, err := f.st.ConfigDocs().Get(t.Context(), store.ConfigNotify, hubconfig.NotifyFile)
		if err != nil || bytes.Contains(stored.Content, []byte(secret)) {
			t.Errorf("the stored notify document is not sealed (%v)", err)
		}
	}
}

func storedNotify(t *testing.T, f *apiFixture) notify.File {
	t.Helper()
	docs, err := hubconfig.Load(t.Context(), f.st.ConfigDocs(), testSealer{})
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := docOf(docs, store.ConfigNotify, hubconfig.NotifyFile)
	file, err := notify.ParseFile(doc.Content)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

const testRunbook = "id: rb\nsteps:\n  - id: wait\n    type: wait\n    duration: 1s\n"

func TestRunbookEditor(t *testing.T) {
	f := newConfigFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	if v := decode[ValidationJSON](t, f.do(t, http.MethodPost, "/api/v1/runbook-files/validate", docBodyJSON(testRunbook, ""), c)); !v.Valid {
		t.Fatalf("validate = %+v", v)
	}
	if v := decode[ValidationJSON](t, f.do(t, http.MethodPost, "/api/v1/runbook-files/validate", docBodyJSON("id: rb\nsteps: 3\n", ""), c)); v.Valid || len(v.Problems) == 0 {
		t.Errorf("validate an invalid runbook = %+v", v)
	}
	if resp := f.do(t, http.MethodPut, "/api/v1/runbook-files/other.yaml", docBodyJSON(testRunbook, ""), c); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a new runbook not named after its id = %d", resp.StatusCode)
	}
	resp := f.do(t, http.MethodPut, "/api/v1/runbook-files/rb.yaml", docBodyJSON(testRunbook, ""), c)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodPut, "/api/v1/runbook-files/rb.yaml", docBodyJSON(testRunbook, ""), c); resp.StatusCode != http.StatusConflict {
		t.Errorf("create again = %d, want 409", resp.StatusCode)
	}
	got := decode[DocJSON](t, f.do(t, http.MethodGet, "/api/v1/runbook-files/rb.yaml", "", c))
	if got.YAML != testRunbook {
		t.Fatalf("get = %+v", got)
	}
	files := decode[struct {
		Files []RunbookFileJSON `json:"files"`
	}](t, f.do(t, http.MethodGet, "/api/v1/runbook-files", "", c)).Files
	if len(files) != 1 || files[0].ID != "rb" {
		t.Errorf("files = %+v", files)
	}
	edited := strings.Replace(testRunbook, "1s", "2s", 1)
	if resp := f.do(t, http.MethodPut, "/api/v1/runbook-files/rb.yaml", docBodyJSON("id: rb\nsteps: 3\n", got.Revision), c); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("save an invalid runbook = %d", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodPut, "/api/v1/runbook-files/rb.yaml", docBodyJSON(edited, "stale"), c); resp.StatusCode != http.StatusConflict {
		t.Errorf("save from a stale revision = %d", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodPut, "/api/v1/runbook-files/rb.yaml", docBodyJSON(edited, got.Revision), c); resp.StatusCode != http.StatusOK {
		t.Fatalf("save = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodDelete, "/api/v1/runbook-files/rb.yaml", "", c); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodDelete, "/api/v1/runbook-files/rb.yaml", "", c); resp.StatusCode != http.StatusNotFound {
		t.Errorf("delete again = %d", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodGet, "/api/v1/runbook-files/..%2Fpolicy.yaml", "", c); resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
		t.Errorf("a path as a name = %d", resp.StatusCode)
	}
	for _, e := range auditOf(t, f, policy.ConfigImport) {
		if strings.Contains(string(e.Detail), "wait") {
			t.Errorf("audit entry holds the runbook's content: %+v", e)
		}
	}
}

func TestDeleteAutomation(t *testing.T) {
	f := newConfigFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	content := "id: nightly\ntriggers:\n  - type: schedule\n    every: 1h\nactions:\n  - type: log\n    message: hi\n"
	if err := f.st.ConfigDocs().Put(t.Context(), "test", []store.ConfigDoc{
		{Kind: store.ConfigAutomation, Name: "nightly.yaml", Content: []byte(content)},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if resp := f.do(t, http.MethodDelete, "/api/v1/automations/nope", "", c); resp.StatusCode != http.StatusNotFound {
		t.Errorf("delete an unknown automation = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodDelete, "/api/v1/automations/nightly", "", c); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d %s", resp.StatusCode, resp.body)
	}
	if _, err := f.st.ConfigDocs().Get(t.Context(), store.ConfigAutomation, "nightly.yaml"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the document is still there: %v", err)
	}
	entries := auditOf(t, f, policy.ConfigImport)
	if len(entries) == 0 || entries[0].ActorKind != policy.ActorWeb || !strings.Contains(string(entries[0].Detail), "automation/nightly.yaml") {
		t.Errorf("audit = %+v", entries)
	}
}

// Without documents in the store the editors are not served.
func TestConfigEditorsNeedDocs(t *testing.T) {
	f := newAPIFixture(t, true)
	c := sessionCookie(t, f.login(t, testPassword))
	for _, path := range []string{"/api/v1/policy", "/api/v1/notify/config", "/api/v1/runbook-files"} {
		if resp := f.do(t, http.MethodGet, path, "", c); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, resp.StatusCode)
		}
	}
}

// newBackupFixture is an API whose store lives in a hub data dir, with its
// CA, so that a backup can be made of it.
func newBackupFixture(t *testing.T) (*apiFixture, string) {
	t.Helper()
	dir := t.TempDir()
	storetest.Migrated(t, filepath.Join(dir, "hearth.db"))
	st, err := store.Open(t.Context(), filepath.Join(dir, "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := pki.LoadOrCreateCA(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	f := newAPIFixture(t, false, func(c *Config) {
		c.Store, c.Policy = st, policy.New(st.Audit())
		c.Registry = NewRegistry(RegistryConfig{Store: st, Log: c.Log})
		c.BackupDir = dir
		c.Backup = func(ctx context.Context, output, passphrase string) error {
			_, err := backup.Create(ctx, backup.CreateOptions{
				DataDir: dir, Store: st, Output: output, Passphrase: passphrase, HearthVersion: "v-test",
			})
			return err
		}
	})
	if err := setAdminPassword(t.Context(), st, f.api.policy, "test", testPassword, testArgon); err != nil {
		t.Fatal(err)
	}
	f.st = st
	return f, dir
}

// The run history lists runs newest first, each step's status without its
// data, such as a command's output.
func TestAutomationRuns(t *testing.T) {
	f := newConfigFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	now := time.Now()
	for i, status := range []string{"ok", "failed"} {
		if err := f.st.AutomationRuns().Record(t.Context(), store.AutomationRun{
			ID: "run-" + status, AutomationID: "nightly", TriggerID: "t", Status: status,
			StartedAt: now.Add(time.Duration(i) * time.Minute), FinishedAt: now.Add(time.Duration(i)*time.Minute + time.Second),
			Steps: json.RawMessage(`[{"id":"a","type":"exec","status":"ok","data":{"stdout":"secret-output-9f"}}]`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	resp := f.do(t, http.MethodGet, "/api/v1/automations/nightly/runs", "", c)
	if resp.StatusCode != http.StatusOK || strings.Contains(string(resp.body), "secret-output-9f") {
		t.Fatalf("runs = %d %s", resp.StatusCode, resp.body)
	}
	runs := decode[struct {
		Runs []AutomationRunJSON `json:"runs"`
	}](t, resp).Runs
	if len(runs) != 2 || runs[0].ID != "run-failed" || len(runs[0].Steps) != 1 || runs[0].Steps[0].Status != "ok" {
		t.Errorf("runs = %+v", runs)
	}
	if resp := f.do(t, http.MethodGet, "/api/v1/automations/nightly/runs?limit=0", "", c); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("limit=0 = %d", resp.StatusCode)
	}
}

func TestMinBackupPassphraseLen(t *testing.T) {
	if MinBackupPassphraseLen != backup.MinPassphraseLen {
		t.Fatalf("MinBackupPassphraseLen = %d, backup.MinPassphraseLen = %d", MinBackupPassphraseLen, backup.MinPassphraseLen)
	}
}

func TestBackupDownload(t *testing.T) {
	const passphrase = "correct horse battery staple"
	f, dir := newBackupFixture(t)
	c := sessionCookie(t, f.login(t, testPassword))
	body := func(p string) string { b, _ := json.Marshal(map[string]string{"passphrase": p}); return string(b) }
	if resp := f.do(t, http.MethodPost, "/api/v1/backup", body(passphrase), staleSession(t, f)); errorCode(t, resp) != "reauth_required" {
		t.Fatalf("backup without re-auth = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/backup", body("short"), c); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a short passphrase = %d", resp.StatusCode)
	}
	resp := f.do(t, http.MethodPost, "/api/v1/backup", body(passphrase), c)
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Disposition"), ".hbk") {
		t.Fatalf("backup = %d %v %.200s", resp.StatusCode, resp.Header, resp.body)
	}
	// It is the archive `hearth backup` writes: it restores, CA key included.
	file := filepath.Join(t.TempDir(), "b.hbk")
	if err := os.WriteFile(file, resp.body, 0o600); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	m, err := backup.Restore(t.Context(), backup.RestoreOptions{Input: file, Passphrase: passphrase, DataDir: restored})
	if err != nil {
		t.Fatalf("restore the download: %v", err)
	}
	if m.NoCAKey || m.HearthVersion != "v-test" {
		t.Errorf("manifest = %+v, want the CA key in", m)
	}
	if _, err := os.Stat(filepath.Join(restored, pki.CAKeyFile)); err != nil {
		t.Errorf("the restore has no CA key: %v", err)
	}
	// Nothing stays behind in the data dir, and the passphrase is nowhere.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), store.BackupTempPrefix) {
			t.Errorf("left behind: %s", e.Name())
		}
	}
	if strings.Contains(f.logs.String(), passphrase) {
		t.Error("the logs hold the passphrase")
	}
	backups := auditOf(t, f, policy.HubBackup)
	if len(backups) < 2 {
		t.Fatalf("audit = %+v, want the refusal and the backup", backups)
	}
	for _, e := range backups {
		if e.ActorKind != policy.ActorWeb || strings.Contains(e.Result+string(e.Detail), passphrase) {
			t.Errorf("audit entry = %+v", e)
		}
	}
}
