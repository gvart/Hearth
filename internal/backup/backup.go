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
	"github.com/gvart/hearth/internal/cluster"
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
	runbooksDir    = "runbooks"
	maxManifest    = 1 << 20
	// maxEntryName is the longest entry name a backup can hold.
	maxEntryName = 255
	// completeMarker is written to the data dir as the last step of a restore.
	completeMarker = "restore-complete"
)

// ErrDataDirNotEmpty refuses a restore over existing data.
var ErrDataDirNotEmpty = errors.New("the data dir is not empty")

// ErrIncompleteRestore means a restore stopped while it moved files into the
// data dir. It matches ErrDataDirNotEmpty.
var ErrIncompleteRestore = fmt.Errorf("%w: it holds an incomplete restore; empty it and restore again", ErrDataDirNotEmpty)

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
	// NoCAKey is true for a backup without the CA private key: it holds the
	// CA certificate only, and a restore needs the key from another backup.
	NoCAKey bool `json:"no_ca_key,omitempty"`
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
	// RunbooksDir is the runbooks directory; empty means <DataDir>/runbooks.
	RunbooksDir string
	// HearthVersion and Clustered go into the manifest.
	HearthVersion string
	Clustered     bool
	// WithoutCAKey leaves the CA private key out of the backup.
	WithoutCAKey bool

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
	if err := PrepareDataDir(opts.DataDir); err != nil {
		return Manifest{}, err
	}
	files, err := configFiles(opts)
	if err != nil {
		return Manifest{}, err
	}
	// The copy stays in the data dir, as private as the database it comes from.
	tmp, removeTmp, err := store.NewTempDir(opts.DataDir, store.BackupTempPrefix)
	if err != nil {
		return Manifest{}, fmt.Errorf("backup: %w", err)
	}
	defer removeTmp()
	snapshot := filepath.Join(tmp, dbName)
	if err := opts.Store.VacuumInto(ctx, snapshot); err != nil {
		return Manifest{}, fmt.Errorf("backup store: %w", err)
	}
	schema, err := opts.Store.SchemaVersion(ctx)
	if err != nil {
		return Manifest{}, fmt.Errorf("backup: %w", err)
	}
	m := Manifest{
		Format: formatVersion, CreatedAt: time.Now().UTC(), HearthVersion: opts.HearthVersion,
		Schema: schema, Clustered: opts.Clustered, NoCAKey: opts.WithoutCAKey,
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
		if !validName(name) {
			return fmt.Errorf("cannot back up %s: a restore could not write this file name; rename the file", name)
		}
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
	// During a hub CA rotation the next CA is there too, and both are needed:
	// the store holds secrets sealed with either key.
	ca := []struct {
		name     string
		optional bool
	}{{pki.CACertFile, false}, {pki.NextCACertFile, true}, {pki.CAKeyFile, false}, {pki.NextCAKeyFile, true}}
	if opts.WithoutCAKey {
		ca = ca[:2]
	}
	for _, f := range ca {
		if err := add(f.name, filepath.Join(opts.DataDir, f.name), f.optional); err != nil {
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
	// Runbooks are listed as the hub loads them, the same way as automations.
	for _, d := range []struct{ entry, dir string }{
		{automationsDir, opts.AutomationsDir}, {runbooksDir, opts.RunbooksDir},
	} {
		dir := d.dir
		if dir == "" {
			dir = filepath.Join(opts.DataDir, d.entry)
		}
		files, err := automation.FileNames(dir)
		if err != nil {
			return nil, fmt.Errorf("backup %s: %w", d.entry, err)
		}
		for _, f := range files {
			if err := add(d.entry+"/"+filepath.Base(f), f, false); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
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
	head := binary.BigEndian.AppendUint16(nil, uint16(len(name))) //nolint:gosec // validName caps a name at maxEntryName bytes
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
	if err := publish(f.Name(), path); errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%w: %s", ErrOutputExists, path)
	} else if err != nil {
		return fmt.Errorf("write backup file: %w", err)
	}
	syncDir(dir)
	return nil
}

// publish moves the file src to dst, and fails with fs.ErrExist rather than
// replace anything at dst. On a filesystem without hard links it claims the
// name with an exclusive create, then renames over its own empty file.
func publish(src, dst string) error {
	err := os.Link(src, dst)
	if err == nil {
		return os.Remove(src)
	}
	if errors.Is(err, fs.ErrExist) {
		return err
	}
	claim, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := claim.Close(); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		_ = os.Remove(dst)
		return err
	}
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

// CheckDataDir refuses a data dir that exists and holds anything, apart from
// the staging directory of a restore that was killed.
func CheckDataDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check data dir: %w", err)
	}
	abandoned, other := false, false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), store.RestoreTempPrefix) && store.AbandonedTempDir(dir, e) {
			abandoned = true
		} else {
			other = true
		}
	}
	switch {
	case abandoned && other:
		return fmt.Errorf("%w: %s", ErrIncompleteRestore, dir)
	case other:
		return fmt.Errorf("%w: %s", ErrDataDirNotEmpty, dir)
	}
	return nil
}

// PrepareDataDir readies a hub data dir for use. It refuses one that a restore
// is still writing or left half done, and deletes the plaintext working files
// of operations that were killed.
func PrepareDataDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check data dir: %w", err)
	}
	var restoring, abandoned, content, complete bool
	for _, e := range entries {
		switch {
		case e.Name() == completeMarker:
			complete = true
		case strings.HasPrefix(e.Name(), store.RestoreTempPrefix):
			if store.AbandonedTempDir(dir, e) {
				abandoned = true
			} else {
				restoring = true
			}
		case !store.IsTempDir(e.Name()):
			content = true
		}
	}
	switch {
	case restoring:
		return fmt.Errorf("a restore into %s is still running", dir)
	case abandoned && content && !complete:
		return fmt.Errorf("%w: %s", ErrIncompleteRestore, dir)
	}
	return store.RemoveAbandonedTempDirs(dir)
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

	info, statErr := os.Stat(opts.DataDir)
	created := errors.Is(statErr, fs.ErrNotExist)
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		return Manifest{}, fmt.Errorf("create data dir: %w", err)
	}
	defer func() {
		switch {
		case err == nil:
		case created:
			_ = os.Remove(opts.DataDir)
		case statErr == nil:
			_ = os.Chmod(opts.DataDir, info.Mode().Perm())
		}
	}()
	if err := os.Chmod(opts.DataDir, 0o700); err != nil { //nolint:gosec // a directory needs its search bit
		return Manifest{}, fmt.Errorf("create data dir: %w", err)
	}
	if err := store.RemoveAbandonedTempDirs(opts.DataDir); err != nil {
		return Manifest{}, fmt.Errorf("restore: %w", err)
	}
	tmp, removeTmp, err := store.NewTempDir(opts.DataDir, store.RestoreTempPrefix)
	if err != nil {
		return Manifest{}, fmt.Errorf("restore: %w", err)
	}
	// Runs before the deferred call above, which removes an empty data dir.
	defer removeTmp()
	// A directory of its own: commit moves everything in it, and the lock stays.
	stage := filepath.Join(tmp, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		return Manifest{}, fmt.Errorf("restore: %w", err)
	}

	if m, err = unpack(ctx, o, stage); err != nil {
		return Manifest{}, err
	}
	if err := verifyStage(ctx, stage, !m.NoCAKey, opts.BeforeCommit); err != nil {
		return Manifest{}, err
	}
	if err := cluster.WriteNewEpoch(stage); err != nil {
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
	for _, name := range []string{dbName, pki.CACertFile} {
		if !seen[name] {
			return Manifest{}, ErrCorrupt
		}
	}
	// The manifest says whether the CA key is in, and the entries agree; the
	// next CA of a rotation has a key only with its certificate and the CA key.
	if seen[pki.CAKeyFile] == m.NoCAKey || seen[pki.NextCAKeyFile] && (!seen[pki.NextCACertFile] || m.NoCAKey) {
		return Manifest{}, ErrCorrupt
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
	if nameLen > maxEntryName {
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
// YAML files directly in the automations or runbooks directory.
func validName(name string) bool {
	if len(name) > maxEntryName {
		return false
	}
	switch name {
	case dbName, pki.CACertFile, pki.CAKeyFile, pki.NextCACertFile, pki.NextCAKeyFile, policy.ConfigFile, notifyName:
		return true
	}
	dir, base := path.Split(name)
	ext := path.Ext(base)
	return (dir == automationsDir+"/" || dir == runbooksDir+"/") && base != "" && !strings.HasPrefix(base, ".") &&
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
	if name == pki.CACertFile || name == pki.NextCACertFile {
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

// verifyStage checks the unpacked CA (its key too, if withKey) and
// database, and retires the old cluster's hub certificates in the restored
// database.
func verifyStage(ctx context.Context, stage string, withKey bool, beforeCommit func(context.Context, *store.Store) error) error {
	certPEM, err := os.ReadFile(filepath.Join(stage, pki.CACertFile))
	if err != nil {
		return fmt.Errorf("restore CA: %w", err)
	}
	if withKey {
		keyPEM, err := os.ReadFile(filepath.Join(stage, pki.CAKeyFile))
		if err != nil {
			return fmt.Errorf("restore CA: %w", err)
		}
		if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
			return errors.New("restore CA: the certificate and key in the backup do not match") // never echo key material
		}
	} else if _, err := pki.ParseCertPEM(certPEM); err != nil {
		return fmt.Errorf("restore CA: %w", err)
	}
	if err := verifyNextCA(stage); err != nil {
		return err
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

// commit moves the staged files into the data dir without replacing anything,
// the database last: a hub never starts on a database without its CA. The
// marker comes after everything else, so a data dir without it, next to an
// abandoned stage, is a restore that stopped half way. On failure commit takes
// back what it moved.
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
	move := func(e fs.DirEntry) error {
		src, dst := filepath.Join(stage, e.Name()), filepath.Join(dataDir, e.Name())
		if !e.IsDir() {
			if err := publish(src, dst); err != nil {
				return fmt.Errorf("restore %s: %w", e.Name(), err)
			}
			moved = append(moved, dst)
			return nil
		}
		if err := os.Mkdir(dst, 0o700); err != nil {
			return fmt.Errorf("restore %s: %w", e.Name(), err)
		}
		moved = append(moved, dst)
		files, err := os.ReadDir(src)
		if err != nil {
			return fmt.Errorf("restore %s: %w", e.Name(), err)
		}
		for _, f := range files {
			if err := publish(filepath.Join(src, f.Name()), filepath.Join(dst, f.Name())); err != nil {
				return fmt.Errorf("restore %s/%s: %w", e.Name(), f.Name(), err)
			}
		}
		return nil
	}
	var db fs.DirEntry
	for _, e := range entries {
		if e.Name() == dbName {
			db = e
			continue
		}
		if err := move(e); err != nil {
			return err
		}
	}
	if db == nil {
		return errors.New("restore: the staged database is missing")
	}
	if err := move(db); err != nil {
		return err
	}
	marker := filepath.Join(dataDir, completeMarker)
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	moved = append(moved, marker)
	if err := f.Close(); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	syncDir(dataDir)
	return nil
}

// verifyNextCA checks the next CA of a hub CA rotation in the stage, if the
// backup holds one: its certificate, and that its key matches it.
func verifyNextCA(stage string) error {
	certPEM, err := os.ReadFile(filepath.Join(stage, pki.NextCACertFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("restore next CA: %w", err)
	}
	if _, err := pki.ParseCertPEM(certPEM); err != nil {
		return fmt.Errorf("restore next CA: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(stage, pki.NextCAKeyFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("restore next CA: %w", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return errors.New("restore next CA: the certificate and key in the backup do not match") // never echo key material
	}
	return nil
}
