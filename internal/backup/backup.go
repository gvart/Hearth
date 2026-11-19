// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// MinPassphraseLen is the shortest passphrase a new backup accepts.
const MinPassphraseLen = 12

// Entry names inside a backup, which are also the file names in a data dir.
const (
	manifestName   = "manifest.json"
	dbName         = "hearth.db"
	notifyName     = "notify.yaml"
	automationsDir = "automations"
	maxManifest    = 1 << 20
)

// ErrDataDirNotEmpty refuses a restore over existing data.
var ErrDataDirNotEmpty = errors.New("the data dir is not empty")

// ErrOutputExists refuses to overwrite an existing backup.
var ErrOutputExists = errors.New("the backup file already exists")

// Manifest describes a backup.
type Manifest struct {
	Format        int       `json:"format"`
	CreatedAt     time.Time `json:"created_at"`
	HearthVersion string    `json:"hearth_version"`
	// Schema is the store's schema version.
	Schema int64 `json:"schema"`
	// Clustered is true for a backup of a Raft cluster member.
	Clustered bool `json:"clustered"`
}

// CreateOptions configures Create.
type CreateOptions struct {
	// DataDir is the hub's data dir.
	DataDir string
	// Store is the open hub store, which may be serving a running hub.
	Store *store.Store
	// Output is the backup file to write; it must not exist.
	Output     string
	Passphrase string
	// NotifyConfig is the notification channels file; empty means
	// <DataDir>/notify.yaml, if there is one.
	NotifyConfig string
	// AutomationsDir is the automations directory; empty means
	// <DataDir>/automations.
	AutomationsDir string
	// HearthVersion and Clustered go into the manifest.
	HearthVersion string
	Clustered     bool

	// kdf overrides the KDF cost, for tests.
	kdf kdfParams
}

// CheckSource fails unless dataDir holds a hub and output is free to write,
// so that a wrong path fails before anything is asked or opened.
func CheckSource(dataDir, output string) error {
	for _, name := range []string{dbName, pki.CACertFile, pki.CAKeyFile} {
		if _, err := os.Stat(filepath.Join(dataDir, name)); err != nil {
			return fmt.Errorf("no hub data in %s (has `hearth hub` been started with this --data-dir?): %w", dataDir, err)
		}
	}
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("%w: %s", ErrOutputExists, output)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("check backup file: %w", err)
	}
	return nil
}

// Create writes an encrypted backup of the hub to opts.Output, atomically and
// with mode 0600. The store copy is consistent while the hub keeps running.
func Create(ctx context.Context, opts CreateOptions) (Manifest, error) {
	if len(opts.Passphrase) < MinPassphraseLen {
		return Manifest{}, fmt.Errorf("the backup passphrase needs at least %d characters", MinPassphraseLen)
	}
	if err := CheckSource(opts.DataDir, opts.Output); err != nil {
		return Manifest{}, err
	}
	files, err := configFiles(opts)
	if err != nil {
		return Manifest{}, err
	}
	// The copy stays in the data dir, as private as the database it comes from.
	tmp, err := os.MkdirTemp(opts.DataDir, ".backup-")
	if err != nil {
		return Manifest{}, fmt.Errorf("backup: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	snapshot := filepath.Join(tmp, dbName)
	if err := writeSnapshot(ctx, opts.Store, snapshot); err != nil {
		return Manifest{}, err
	}
	schema, err := opts.Store.SchemaVersion(ctx)
	if err != nil {
		return Manifest{}, fmt.Errorf("backup: %w", err)
	}
	m := Manifest{
		Format: formatVersion, CreatedAt: time.Now().UTC(), HearthVersion: opts.HearthVersion,
		Schema: schema, Clustered: opts.Clustered,
	}
	kdf := opts.kdf
	if kdf == (kdfParams{}) {
		kdf = defaultKDF()
	}
	err = writeAtomic(opts.Output, func(w io.Writer) error {
		return writeArchive(ctx, w, opts.Passphrase, kdf, m, files, snapshot)
	})
	if err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// namedFile is one configuration file of a backup.
type namedFile struct {
	name string
	data []byte
}

// configFiles reads the CA and the per-hub configuration into memory: all of
// them are small. Automations are the files the hub loads.
func configFiles(opts CreateOptions) ([]namedFile, error) {
	var out []namedFile
	add := func(name, src string, optional bool) error {
		b, err := os.ReadFile(src)
		if optional && errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("backup %s: %w", name, err)
		}
		out = append(out, namedFile{name: name, data: b})
		return nil
	}
	for _, name := range []string{pki.CACertFile, pki.CAKeyFile} {
		if err := add(name, filepath.Join(opts.DataDir, name), false); err != nil {
			return nil, err
		}
	}
	if err := add(policy.ConfigFile, filepath.Join(opts.DataDir, policy.ConfigFile), true); err != nil {
		return nil, err
	}
	notify := opts.NotifyConfig
	if notify == "" {
		notify = filepath.Join(opts.DataDir, notifyName)
	}
	// A file named explicitly must exist, as the hub requires too.
	if err := add(notifyName, notify, opts.NotifyConfig == ""); err != nil {
		return nil, err
	}
	dir := opts.AutomationsDir
	if dir == "" {
		dir = filepath.Join(opts.DataDir, automationsDir)
	}
	autos, err := automation.Files(dir)
	if err != nil {
		return nil, fmt.Errorf("backup automations: %w", err)
	}
	for _, f := range autos {
		if err := add(automationsDir+"/"+filepath.Base(f), f, false); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func writeSnapshot(ctx context.Context, st *store.Store, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("backup store: %w", err)
	}
	if err := st.Snapshot(ctx, f); err != nil {
		_ = f.Close()
		return fmt.Errorf("backup store: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("backup store: %w", err)
	}
	return nil
}

// writeArchive writes the header and the sealed entries to w.
func writeArchive(ctx context.Context, w io.Writer, passphrase string, kdf kdfParams, m Manifest, files []namedFile, snapshot string) error {
	s, err := newSealer(w, passphrase, kdf)
	if err != nil {
		return err
	}
	mb, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("backup manifest: %w", err)
	}
	if err := writeEntry(s, manifestName, int64(len(mb)), strings.NewReader(string(mb))); err != nil {
		return err
	}
	for _, f := range files {
		if err := writeEntry(s, f.name, int64(len(f.data)), strings.NewReader(string(f.data))); err != nil {
			return err
		}
	}
	db, err := os.Open(snapshot)
	if err != nil {
		return fmt.Errorf("backup store: %w", err)
	}
	defer func() { _ = db.Close() }()
	info, err := db.Stat()
	if err != nil {
		return fmt.Errorf("backup store: %w", err)
	}
	if err := writeEntry(s, dbName, info.Size(), ctxReader{ctx: ctx, r: db}); err != nil {
		return err
	}
	if _, err := s.Write([]byte{0, 0}); err != nil { // the end of the entries
		return err
	}
	return s.Close()
}

func writeEntry(w io.Writer, name string, size int64, r io.Reader) error {
	head := binary.BigEndian.AppendUint16(nil, uint16(len(name))) //nolint:gosec // names are short and from a fixed set
	head = append(head, name...)
	head = binary.BigEndian.AppendUint64(head, uint64(size)) //nolint:gosec // a file size is never negative
	if _, err := w.Write(head); err != nil {
		return err
	}
	if _, err := io.CopyN(w, r, size); err != nil {
		return fmt.Errorf("backup %s: %w", name, err)
	}
	return nil
}

// ctxReader stops a long copy when ctx ends.
type ctxReader struct {
	ctx context.Context //nolint:containedctx // scoped to one copy
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// writeAtomic writes path through a private temp file next to it, so a backup
// file is either complete or absent.
func writeAtomic(path string, write func(io.Writer) error) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".hearth-backup-*")
	if err != nil {
		return fmt.Errorf("create backup file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("create backup file: %w", err)
	}
	if err := write(f); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("write backup file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write backup file: %w", err)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("write backup file: %w", err)
	}
	syncDir(dir)
	return nil
}

// syncDir makes a rename durable, where the platform supports it.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// RestoreOptions configures Restore.
type RestoreOptions struct {
	// Input is the backup file.
	Input      string
	Passphrase string
	// DataDir is the hub data dir to create. It must be missing or empty.
	DataDir string
	// BeforeCommit runs on the restored store once every check passed, just
	// before the files move into the data dir. An error aborts the restore.
	BeforeCommit func(context.Context, *store.Store) error
}

// CheckDataDir refuses a data dir that exists and holds anything.
func CheckDataDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check data dir: %w", err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("%w: %s", ErrDataDirNotEmpty, dir)
	}
	return nil
}

// Restore unpacks the backup into a staging directory inside opts.DataDir,
// verifies all of it, and only then moves the files into place. When it fails
// the data dir is left as empty as it was found.
func Restore(ctx context.Context, opts RestoreOptions) (m Manifest, err error) {
	if err := CheckDataDir(opts.DataDir); err != nil {
		return Manifest{}, err
	}
	in, err := os.Open(opts.Input)
	if err != nil {
		return Manifest{}, fmt.Errorf("open backup: %w", err)
	}
	defer func() { _ = in.Close() }()
	o, err := newOpener(in, opts.Passphrase)
	if err != nil {
		return Manifest{}, err
	}

	_, statErr := os.Stat(opts.DataDir)
	created := errors.Is(statErr, fs.ErrNotExist)
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		return Manifest{}, fmt.Errorf("create data dir: %w", err)
	}
	if err := os.Chmod(opts.DataDir, 0o700); err != nil { //nolint:gosec // a directory needs its search bit
		return Manifest{}, fmt.Errorf("create data dir: %w", err)
	}
	stage, err := os.MkdirTemp(opts.DataDir, ".restore-")
	if err != nil {
		return Manifest{}, fmt.Errorf("restore: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(stage)
		if err != nil && created {
			_ = os.Remove(opts.DataDir)
		}
	}()

	if m, err = unpack(ctx, o, stage); err != nil {
		return Manifest{}, err
	}
	if err := verifyStage(ctx, stage, opts.BeforeCommit); err != nil {
		return Manifest{}, err
	}
	if err := commit(stage, opts.DataDir); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// unpack writes the entries of o into stage and returns the manifest. It reads
// o to its end, so nothing returned here came from a truncated file.
func unpack(ctx context.Context, o *opener, stage string) (Manifest, error) {
	r := ctxReader{ctx: ctx, r: o}
	name, size, err := readEntryHead(r)
	if err != nil {
		return Manifest{}, err
	}
	if name != manifestName || size > maxManifest {
		return Manifest{}, ErrCorrupt
	}
	mb := make([]byte, size)
	if _, err := io.ReadFull(r, mb); err != nil {
		return Manifest{}, readErr(err)
	}
	var m Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return Manifest{}, ErrCorrupt
	}
	if m.Schema > store.SchemaVersion() {
		return Manifest{}, fmt.Errorf("%w: the backup is at schema %d, this binary supports up to %d; "+
			"restore it with the Hearth version that wrote it (%s) or a newer one",
			store.ErrSchemaMismatch, m.Schema, store.SchemaVersion(), m.HearthVersion)
	}
	seen := map[string]bool{}
	for {
		name, size, err := readEntryHead(r)
		if err != nil {
			return Manifest{}, err
		}
		if name == "" {
			break
		}
		if !validName(name) || seen[name] {
			return Manifest{}, ErrCorrupt
		}
		seen[name] = true
		if err := unpackFile(r, stage, name, size); err != nil {
			return Manifest{}, err
		}
	}
	for _, name := range []string{dbName, pki.CACertFile, pki.CAKeyFile} {
		if !seen[name] {
			return Manifest{}, ErrCorrupt
		}
	}
	// The final chunk must follow the end of the entries, with nothing after.
	if n, err := r.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		if err != nil && !errors.Is(err, io.EOF) {
			return Manifest{}, readErr(err)
		}
		return Manifest{}, ErrCorrupt
	}
	return m, nil
}

// readErr maps a short read of the decrypted stream to ErrCorrupt.
func readErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrCorrupt
	}
	return err
}

// readEntryHead reads the next entry's name and size; the name is empty at the
// end of the entries.
func readEntryHead(r io.Reader) (string, int64, error) {
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return "", 0, readErr(err)
	}
	nameLen := binary.BigEndian.Uint16(n[:])
	if nameLen == 0 {
		return "", 0, nil
	}
	if nameLen > 255 {
		return "", 0, ErrCorrupt
	}
	name := make([]byte, nameLen)
	if _, err := io.ReadFull(r, name); err != nil {
		return "", 0, readErr(err)
	}
	var s [8]byte
	if _, err := io.ReadFull(r, s[:]); err != nil {
		return "", 0, readErr(err)
	}
	size := binary.BigEndian.Uint64(s[:])
	if size > 1<<62 {
		return "", 0, ErrCorrupt
	}
	return string(name), int64(size), nil
}

// validName reports whether an entry may be unpacked: a fixed set of files, and
// automation files directly in the automations directory.
func validName(name string) bool {
	switch name {
	case dbName, pki.CACertFile, pki.CAKeyFile, policy.ConfigFile, notifyName:
		return true
	}
	dir, base := path.Split(name)
	ext := path.Ext(base)
	return dir == automationsDir+"/" && base != "" && !strings.HasPrefix(base, ".") &&
		!strings.ContainsAny(base, `/\`) && (ext == ".yaml" || ext == ".yml")
}

// unpackFile writes one entry into stage. Everything is private to the hub's
// user except the CA certificate, which is public.
func unpackFile(r io.Reader, stage, name string, size int64) error {
	dst := filepath.Join(stage, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("restore %s: %w", name, err)
	}
	mode := os.FileMode(0o600)
	if name == pki.CACertFile {
		mode = 0o644
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("restore %s: %w", name, err)
	}
	if _, err := io.CopyN(f, r, size); err != nil {
		_ = f.Close()
		if rerr := readErr(err); errors.Is(rerr, ErrCorrupt) {
			return rerr
		}
		return fmt.Errorf("restore %s: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("restore %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("restore %s: %w", name, err)
	}
	return nil
}

// verifyStage checks the unpacked CA and database, and retires the old
// cluster's hub certificates in the restored database.
func verifyStage(ctx context.Context, stage string, beforeCommit func(context.Context, *store.Store) error) error {
	certPEM, err := os.ReadFile(filepath.Join(stage, pki.CACertFile))
	if err != nil {
		return fmt.Errorf("restore CA: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(stage, pki.CAKeyFile))
	if err != nil {
		return fmt.Errorf("restore CA: %w", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return errors.New("restore CA: the certificate and key in the backup do not match") // never echo key material
	}
	dbPath := filepath.Join(stage, dbName)
	if err := store.CheckSnapshotFile(ctx, dbPath); err != nil {
		return fmt.Errorf("restore store: %w", err)
	}
	st, err := store.Open(ctx, dbPath, store.WithoutUpgrade())
	if err != nil {
		return fmt.Errorf("restore store: %w", err)
	}
	err = st.RetireHubCerts(ctx, time.Now())
	if err == nil && beforeCommit != nil {
		err = beforeCommit(ctx, st)
	}
	if cerr := st.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("restore store: %w", err)
	}
	return nil
}

// commit moves the staged files into the data dir, the database last: a hub
// never starts on a database without its CA. On failure it takes back what it
// moved.
func commit(stage, dataDir string) (err error) {
	entries, err := os.ReadDir(stage)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	var moved []string
	defer func() {
		if err != nil {
			for _, p := range moved {
				_ = os.RemoveAll(p)
			}
		}
	}()
	move := func(name string) error {
		dst := filepath.Join(dataDir, name)
		if err := os.Rename(filepath.Join(stage, name), dst); err != nil {
			return fmt.Errorf("restore %s: %w", name, err)
		}
		moved = append(moved, dst)
		return nil
	}
	for _, e := range entries {
		if e.Name() == dbName {
			continue
		}
		if err := move(e.Name()); err != nil {
			return err
		}
	}
	if err := move(dbName); err != nil {
		return err
	}
	syncDir(dataDir)
	return nil
}
