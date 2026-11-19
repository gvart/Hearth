// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

const (
	testPassphrase = "correct horse battery staple"
	notifySecret   = "channels: {phone: {type: ntfy, url: 'http://ntfy.lan', topic: s3cr3t-topic}}\n"
)

// testKDF keeps the tests fast; the cost is stored in each file.
var testKDF = kdfParams{time: 1, memory: 64, threads: 1}

// newHub creates a data dir as a hub leaves it, with one enrolled device.
func newHub(t *testing.T) (string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	if _, err := pki.LoadOrCreateCA(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.Context(), filepath.Join(dir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now()
	if err := st.Devices().Upsert(t.Context(), store.Device{
		ID: "dev-1", Name: "pi", FirstSeen: now, LastSeen: now, Status: store.StatusOffline,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Certs().Create(t.Context(), "serial-1", "dev-1"); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "policy.yaml"), "classes: {dangerous: confirm}\n")
	writeTestFile(t, filepath.Join(dir, notifyName), notifySecret)
	writeTestFile(t, filepath.Join(dir, automationsDir, "lights.yaml"), "id: lights\n")
	writeTestFile(t, filepath.Join(dir, automationsDir, ".hidden.yaml"), "id: hidden\n")
	writeTestFile(t, filepath.Join(dir, automationsDir, "notes.txt"), "not an automation\n")
	return dir, st
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func createOpts(dir string, st *store.Store, output string) CreateOptions {
	return CreateOptions{
		DataDir: dir, Store: st, Output: output, Passphrase: testPassphrase,
		HearthVersion: "test", kdf: testKDF,
	}
}

// newBackup writes a backup of a new hub and returns the file's path.
func newBackup(t *testing.T) string {
	t.Helper()
	dir, st := newHub(t)
	out := filepath.Join(t.TempDir(), "hub.hbk")
	if _, err := Create(t.Context(), createOpts(dir, st, out)); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRoundTrip(t *testing.T) {
	dir, st := newHub(t)
	out := filepath.Join(t.TempDir(), "hub.hbk")
	m, err := Create(t.Context(), createOpts(dir, st, out))
	if err != nil {
		t.Fatal(err)
	}
	if m.Schema != store.SchemaVersion() || m.HearthVersion != "test" || m.Clustered {
		t.Errorf("manifest = %+v", m)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("backup mode = %o, want 600", info.Mode().Perm())
	}

	target := filepath.Join(t.TempDir(), "restored")
	got, err := Restore(t.Context(), RestoreOptions{Input: out, Passphrase: testPassphrase, DataDir: target})
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != m.Schema || !got.CreatedAt.Equal(m.CreatedAt) {
		t.Errorf("restored manifest = %+v, want %+v", got, m)
	}
	for _, name := range []string{pki.CACertFile, pki.CAKeyFile, "policy.yaml", notifyName, "automations/lights.yaml"} {
		want, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		have, err := os.ReadFile(filepath.Join(target, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, have) {
			t.Errorf("%s differs after the restore", name)
		}
	}
	for name, want := range map[string]fs.FileMode{
		".": 0o700, pki.CAKeyFile: 0o600, pki.CACertFile: 0o644, notifyName: 0o600, dbName: 0o600,
	} {
		info, err := os.Stat(filepath.Join(target, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode = %o, want %o", name, info.Mode().Perm(), want)
		}
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") || e.Name() == "raft" {
			t.Errorf("unexpected %s in the restored data dir", e.Name())
		}
	}
	for _, name := range []string{".hidden.yaml", "notes.txt"} {
		if _, err := os.Stat(filepath.Join(target, automationsDir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s was restored: %v", name, err)
		}
	}

	rs, err := store.Open(t.Context(), filepath.Join(target, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	if _, err := rs.Devices().Get(t.Context(), "dev-1"); err != nil {
		t.Errorf("device after the restore: %v", err)
	}
	if err := rs.Certs().Check(t.Context(), "serial-1", "dev-1"); err != nil {
		t.Errorf("device certificate after the restore: %v", err)
	}
}

func TestCreateReadsConfigOutsideTheDataDir(t *testing.T) {
	dir, st := newHub(t)
	other := t.TempDir()
	writeTestFile(t, filepath.Join(other, "channels.yaml"), "channels: {}\n")
	writeTestFile(t, filepath.Join(other, "autos", "door.yml"), "id: door\n")
	opts := createOpts(dir, st, filepath.Join(t.TempDir(), "hub.hbk"))
	opts.NotifyConfig = filepath.Join(other, "channels.yaml")
	opts.AutomationsDir = filepath.Join(other, "autos")
	if _, err := Create(t.Context(), opts); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(t.Context(), RestoreOptions{Input: opts.Output, Passphrase: testPassphrase, DataDir: target}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(target, notifyName))
	if err != nil || string(b) != "channels: {}\n" {
		t.Errorf("notify.yaml = %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(target, automationsDir, "door.yml")); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(filepath.Join(target, automationsDir, "lights.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the data dir's automations were backed up instead: %v", err)
	}
}

func TestCreateRefuses(t *testing.T) {
	dir, st := newHub(t)
	existing := filepath.Join(t.TempDir(), "exists.hbk")
	writeTestFile(t, existing, "keep me")
	tests := []struct {
		name string
		mod  func(*CreateOptions)
		want error
	}{
		{"short passphrase", func(o *CreateOptions) { o.Passphrase = "short" }, nil},
		{"empty passphrase", func(o *CreateOptions) { o.Passphrase = "" }, nil},
		{"existing output", func(o *CreateOptions) { o.Output = existing }, ErrOutputExists},
		{"no hub in the data dir", func(o *CreateOptions) { o.DataDir = t.TempDir() }, fs.ErrNotExist},
		{"named notify file missing", func(o *CreateOptions) { o.NotifyConfig = filepath.Join(dir, "nope.yaml") }, fs.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "hub.hbk")
			opts := createOpts(dir, st, out)
			tt.mod(&opts)
			_, err := Create(t.Context(), opts)
			if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) {
				t.Fatalf("Create = %v, want %v", err, tt.want)
			}
			if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a backup was written: %v", err)
			}
		})
	}
	if b, _ := os.ReadFile(existing); string(b) != "keep me" {
		t.Errorf("existing file overwritten: %q", b)
	}
}

func TestFailedCreateLeavesNothingBehind(t *testing.T) {
	dir, st := newHub(t)
	outDir := t.TempDir()
	opts := createOpts(dir, st, filepath.Join(outDir, "hub.hbk"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Create(ctx, opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("Create = %v, want context.Canceled", err)
	}
	for _, d := range []string{outDir, dir} {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") || strings.HasSuffix(e.Name(), ".hbk") {
				t.Errorf("left behind in %s: %s", d, e.Name())
			}
		}
	}
}

func TestBackupHidesSecrets(t *testing.T) {
	dir, st := newHub(t)
	out := filepath.Join(t.TempDir(), "hub.hbk")
	if _, err := Create(t.Context(), createOpts(dir, st, out)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"PRIVATE KEY", "s3cr3t-topic", "SQLite format", "manifest.json", testPassphrase} {
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("the backup file shows %q in the clear", secret)
		}
	}
}

// assertRefused restores input into a missing and an empty data dir, expecting
// want both times and no file left behind.
func assertRefused(t *testing.T, input, passphrase string, want error) {
	t.Helper()
	missing := filepath.Join(t.TempDir(), "missing")
	_, err := Restore(t.Context(), RestoreOptions{Input: input, Passphrase: passphrase, DataDir: missing})
	if !errors.Is(err, want) {
		t.Fatalf("Restore = %v, want %v", err, want)
	}
	if strings.Contains(err.Error(), passphrase) && passphrase != "" {
		t.Errorf("the error shows the passphrase: %v", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a failed restore left the data dir behind: %v", err)
	}
	empty := t.TempDir()
	if _, err := Restore(t.Context(), RestoreOptions{Input: input, Passphrase: passphrase, DataDir: empty}); !errors.Is(err, want) {
		t.Fatalf("Restore into an empty dir = %v, want %v", err, want)
	}
	entries, err := os.ReadDir(empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a failed restore left %d entries, the first %s", len(entries), entries[0].Name())
	}
}

func TestRestoreWrongPassphrase(t *testing.T) {
	assertRefused(t, newBackup(t), "not the right passphrase", ErrWrongPassphrase)
}

// largeBackup is a backup of several chunks, for damage at chunk boundaries.
func largeBackup(t *testing.T) []byte {
	t.Helper()
	dir, st := newHub(t)
	// Random content does not shrink, so the file spans several chunks.
	big := make([]byte, 3*chunkSize)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "policy.yaml"), string(big))
	out := filepath.Join(t.TempDir(), "hub.hbk")
	if _, err := Create(t.Context(), createOpts(dir, st, out)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRestoreDamagedBackup(t *testing.T) {
	orig := largeBackup(t)
	sealed := chunkSize + 16
	flip := func(off int) func([]byte) []byte {
		return func(b []byte) []byte {
			if off < 0 {
				off += len(b)
			}
			b[off] ^= 0x40
			return b
		}
	}
	cut := func(n int) func([]byte) []byte {
		return func(b []byte) []byte { return b[:n] }
	}
	tests := []struct {
		name string
		mod  func([]byte) []byte
		want error
	}{
		{"flipped magic", flip(0), ErrNotBackup},
		{"newer format", func(b []byte) []byte { b[len(magic)] = formatVersion + 1; return b }, ErrUnsupportedFormat},
		{"flipped kdf time", flip(len(magic) + 4), ErrCorrupt},
		{"flipped salt", flip(len(magic) + 11), ErrWrongPassphrase},
		{"flipped nonce prefix", flip(macOffset - 1), ErrWrongPassphrase},
		{"flipped header mac", flip(macOffset), ErrWrongPassphrase},
		{"flipped first chunk", flip(headerLen), ErrCorrupt},
		{"flipped middle chunk", flip(headerLen + sealed + 100), ErrCorrupt},
		{"flipped last byte", flip(-1), ErrCorrupt},
		{"empty file", cut(0), ErrCorrupt},
		{"cut inside the magic", cut(3), ErrCorrupt},
		{"cut inside the header", cut(headerLen - 1), ErrCorrupt},
		{"cut after the header", cut(headerLen), ErrCorrupt},
		{"cut inside a chunk", cut(headerLen + 100), ErrCorrupt},
		{"cut at a chunk boundary", cut(headerLen + sealed), ErrCorrupt},
		{"cut at the second chunk boundary", cut(headerLen + 2*sealed), ErrCorrupt},
		{"last byte missing", func(b []byte) []byte { return b[:len(b)-1] }, ErrCorrupt},
		{"appended bytes", func(b []byte) []byte { return append(b, 0) }, ErrCorrupt},
		{"appended chunk", func(b []byte) []byte { return append(b, b[headerLen:headerLen+sealed]...) }, ErrCorrupt},
		{"chunk dropped", func(b []byte) []byte {
			return append(b[:headerLen:headerLen], b[headerLen+sealed:]...)
		}, ErrCorrupt},
		{"chunks swapped", func(b []byte) []byte {
			first := bytes.Clone(b[headerLen : headerLen+sealed])
			copy(b[headerLen:], b[headerLen+sealed:headerLen+2*sealed])
			copy(b[headerLen+sealed:], first)
			return b
		}, ErrCorrupt},
		{"not a backup", func([]byte) []byte {
			return []byte("just some text, long enough to fill a whole header of a backup file....")
		}, ErrNotBackup},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "damaged.hbk")
			if err := os.WriteFile(path, tt.mod(bytes.Clone(orig)), 0o600); err != nil {
				t.Fatal(err)
			}
			assertRefused(t, path, testPassphrase, tt.want)
		})
	}
}

// TestStreamRefusesReorderedChunks checks the sealed stream on its own: inside
// one large entry, the entry framing cannot notice chunks that were moved.
func TestStreamRefusesReorderedChunks(t *testing.T) {
	const chunks = 4
	var sealed bytes.Buffer
	s, err := newSealer(&sealed, testPassphrase, testKDF)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, chunks*chunkSize)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	orig := sealed.Bytes()
	size := chunkSize + 16
	chunk := func(b []byte, i int) []byte { return b[headerLen+i*size : headerLen+(i+1)*size] }

	got, err := io.ReadAll(mustOpen(t, orig))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("intact stream: %d bytes, %v", len(got), err)
	}
	tests := map[string]func([]byte) []byte{
		"middle chunks swapped": func(b []byte) []byte {
			first := bytes.Clone(chunk(b, 1))
			copy(chunk(b, 1), chunk(b, 2))
			copy(chunk(b, 2), first)
			return b
		},
		"middle chunk dropped": func(b []byte) []byte {
			return append(b[:headerLen+size:headerLen+size], b[headerLen+2*size:]...)
		},
		"cut at a chunk boundary": func(b []byte) []byte { return b[:headerLen+2*size] },
		"final chunk repeated":    func(b []byte) []byte { return append(b, chunk(b, chunks-1)...) },
	}
	for name, mod := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := io.ReadAll(mustOpen(t, mod(bytes.Clone(orig)))); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("read = %v, want ErrCorrupt", err)
			}
		})
	}
}

func mustOpen(t *testing.T, b []byte) *opener {
	t.Helper()
	o, err := newOpener(bytes.NewReader(b), testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestRestoreRefusesACostlyHeader(t *testing.T) {
	var buf bytes.Buffer
	if _, err := newSealer(&buf, testPassphrase, testKDF); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		off  int
		val  byte
	}{
		{"huge memory", len(magic) + 5, 0xff},
		{"huge time", len(magic) + 1, 0xff},
		{"zero threads", len(magic) + 9, 0},
		{"many threads", len(magic) + 9, 0xff},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Clone(buf.Bytes())
			b[tt.off] = tt.val
			path := filepath.Join(t.TempDir(), "costly.hbk")
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			assertRefused(t, path, testPassphrase, ErrCorrupt)
		})
	}
}

func TestRestoreRefusesNonEmptyDataDir(t *testing.T) {
	input := newBackup(t)
	for _, name := range []string{"hearth.db", ".hidden"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, filepath.Join(dir, name), "existing data")
			_, err := Restore(t.Context(), RestoreOptions{Input: input, Passphrase: testPassphrase, DataDir: dir})
			if !errors.Is(err, ErrDataDirNotEmpty) {
				t.Fatalf("Restore = %v, want ErrDataDirNotEmpty", err)
			}
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || string(b) != "existing data" {
				t.Errorf("existing file = %q, %v", b, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Errorf("data dir has %d entries, %v", len(entries), err)
			}
		})
	}
}

// craftBackup seals a backup from parts, as a tampering or newer writer would.
func craftBackup(t *testing.T, m Manifest, files []namedFile, snapshot string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "crafted.hbk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := writeArchive(t.Context(), f, testPassphrase, testKDF, m, files, snapshot); err != nil {
		t.Fatal(err)
	}
	return path
}

// hubParts returns the CA files and a store snapshot of a new hub.
func hubParts(t *testing.T) ([]namedFile, string) {
	t.Helper()
	dir, st := newHub(t)
	var files []namedFile
	for _, name := range []string{pki.CACertFile, pki.CAKeyFile} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, namedFile{name: name, data: b})
	}
	snapshot := filepath.Join(t.TempDir(), dbName)
	if err := writeSnapshot(t.Context(), st, snapshot); err != nil {
		t.Fatal(err)
	}
	return files, snapshot
}

func TestRestoreRefusesNewerSchema(t *testing.T) {
	files, _ := hubParts(t)
	newer := store.SchemaVersion() + 1
	path := filepath.Join(t.TempDir(), dbName)
	st, err := store.Open(t.Context(), path, store.WithExtraMigration(newer, `CREATE TABLE from_the_future (id INTEGER)`))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	snapshot := filepath.Join(t.TempDir(), dbName)
	if err := writeSnapshot(t.Context(), st, snapshot); err != nil {
		t.Fatal(err)
	}
	// The manifest is checked first; the database itself is checked as well.
	for name, schema := range map[string]int64{"manifest says so": newer, "only the database says so": store.SchemaVersion()} {
		t.Run(name, func(t *testing.T) {
			input := craftBackup(t, Manifest{Format: formatVersion, Schema: schema}, files, snapshot)
			assertRefused(t, input, testPassphrase, store.ErrSchemaMismatch)
		})
	}
}

func TestRestoreAcceptsAnOlderSchema(t *testing.T) {
	files, snapshot := hubParts(t)
	input := craftBackup(t, Manifest{Format: formatVersion, Schema: store.SchemaVersion() - 1}, files, snapshot)
	target := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(t.Context(), RestoreOptions{Input: input, Passphrase: testPassphrase, DataDir: target}); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreRefusesBadEntries(t *testing.T) {
	files, snapshot := hubParts(t)
	m := Manifest{Format: formatVersion, Schema: store.SchemaVersion()}
	with := func(extra ...namedFile) []namedFile { return append(append([]namedFile{}, files...), extra...) }
	tests := map[string][]namedFile{
		"parent traversal":      with(namedFile{"../evil.yaml", []byte("x")}),
		"traversal in a subdir": with(namedFile{"automations/../../evil.yaml", []byte("x")}),
		"absolute path":         with(namedFile{"/tmp/evil.yaml", []byte("x")}),
		"nested automation":     with(namedFile{"automations/sub/evil.yaml", []byte("x")}),
		"hidden automation":     with(namedFile{"automations/.evil.yaml", []byte("x")}),
		"not an automation":     with(namedFile{"automations/evil.sh", []byte("x")}),
		"raft state":            with(namedFile{"raft/raft.db", []byte("x")}),
		"unknown file":          with(namedFile{"authorized_keys", []byte("x")}),
		"duplicate entry":       with(files[0]),
		"no CA key":             files[:1],
		"key of another CA":     {files[0], {pki.CAKeyFile, otherCAKey(t)}},
	}
	for name, entries := range tests {
		t.Run(name, func(t *testing.T) {
			input := craftBackup(t, m, entries, snapshot)
			target := filepath.Join(t.TempDir(), "restored")
			if _, err := Restore(t.Context(), RestoreOptions{Input: input, Passphrase: testPassphrase, DataDir: target}); err == nil {
				t.Fatal("Restore accepted the backup")
			}
			if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("data dir left behind: %v", err)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(target), "evil.yaml")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a file escaped the data dir: %v", err)
			}
		})
	}
}

func otherCAKey(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	if _, err := pki.LoadOrCreateCA(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, pki.CAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRestoreBeforeCommitFailure(t *testing.T) {
	input := newBackup(t)
	target := t.TempDir()
	boom := errors.New("boom")
	_, err := Restore(t.Context(), RestoreOptions{
		Input: input, Passphrase: testPassphrase, DataDir: target,
		BeforeCommit: func(context.Context, *store.Store) error { return boom },
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Restore = %v, want boom", err)
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Errorf("data dir has %d entries after a failed commit: %v", len(entries), err)
	}
}

// TestRestoreRetiresOldHubCerts: the old cluster's hubs share the restored CA,
// so their certificates must not work against the restored hub.
func TestRestoreRetiresOldHubCerts(t *testing.T) {
	dir, st := newHub(t)
	if err := st.Hubs().RecordCert(t.Context(), "old-serial", "hub-b"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "hub.hbk")
	if _, err := Create(t.Context(), createOpts(dir, st, out)); err != nil {
		t.Fatal(err)
	}
	if err := st.Hubs().CheckCert(t.Context(), "old-serial"); err != nil {
		t.Fatalf("the backup changed the live hub: %v", err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(t.Context(), RestoreOptions{Input: out, Passphrase: testPassphrase, DataDir: target}); err != nil {
		t.Fatal(err)
	}
	rs, err := store.Open(t.Context(), filepath.Join(target, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	if err := rs.Hubs().CheckCert(t.Context(), "old-serial"); !errors.Is(err, store.ErrCertRevoked) {
		t.Errorf("old hub certificate after the restore: %v, want ErrCertRevoked", err)
	}
}

// TestBackupWhileWriting takes a backup while another connection keeps writing:
// the copy must be an intact database holding a gapless prefix of the writes.
func TestBackupWhileWriting(t *testing.T) {
	dir, st := newHub(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var written atomic.Int64
	done := make(chan error, 1)
	go func() {
		for i := 0; ; i++ {
			if ctx.Err() != nil {
				done <- nil
				return
			}
			detail, _ := json.Marshal(map[string]int{"seq": i})
			if _, err := st.Audit().Append(ctx, store.AuditEntry{
				ActorKind: "test", ActorID: "writer", Action: "test.write", Decision: "allow", Detail: detail,
			}); err != nil {
				if ctx.Err() != nil {
					done <- nil
					return
				}
				done <- fmt.Errorf("write %d: %w", i, err)
				return
			}
			written.Add(1)
		}
	}()
	for written.Load() < 20 {
		time.Sleep(time.Millisecond)
	}
	out := filepath.Join(t.TempDir(), "hub.hbk")
	if _, err := Create(t.Context(), createOpts(dir, st, out)); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(t.Context(), RestoreOptions{Input: out, Passphrase: testPassphrase, DataDir: target}); err != nil {
		t.Fatal(err)
	}
	rs, err := store.Open(t.Context(), filepath.Join(target, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	entries, err := rs.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{"test.write"}}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("the backup holds none of the writes made before it")
	}
	for i, e := range entries { // newest first
		var d struct{ Seq int }
		if err := json.Unmarshal(e.Detail, &d); err != nil {
			t.Fatal(err)
		}
		if want := len(entries) - 1 - i; d.Seq != want {
			t.Fatalf("entry %d has seq %d, want %d: the copy is not a prefix of the writes", i, d.Seq, want)
		}
	}
}
