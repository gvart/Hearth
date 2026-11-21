// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// MinBackupPassphraseLen is backup.MinPassphraseLen, which this package cannot
// import: the shortest passphrase `hearth backup` accepts.
const MinBackupPassphraseLen = 12

// backupRoutes registers the web UI's backup download. Without Config.Backup
// there is none.
func (a *api) backupRoutes(mux *http.ServeMux) {
	if a.backup == nil || a.backupDir == "" {
		return
	}
	mux.Handle("POST /api/v1/backup", a.auth(a.downloadBackup))
}

// downloadBackup writes an encrypted backup of the hub, as `hearth backup`
// does, with the CA key, and streams it to the browser: dangerous, only with
// the password entered again, and audited. The passphrase comes in the body,
// never the URL, and is never logged; the file is written to a private
// directory of the data dir and removed once sent.
func (a *api) downloadBackup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if !decodeJSON(w, r, maxLoginBody, &body, `{"passphrase": "..."}`) {
		return
	}
	if len(body.Passphrase) < MinBackupPassphraseLen {
		writeError(w, http.StatusBadRequest, "bad_passphrase",
			fmt.Sprintf("the backup passphrase needs at least %d characters", MinBackupPassphraseLen))
		return
	}
	name := "hearth-" + a.now().UTC().Format("20060102T150405Z") + ".hbk"
	var (
		path   string
		remove func()
	)
	defer func() {
		if remove != nil {
			remove()
		}
	}()
	err := a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.HubBackup, Target: name,
		Detail: map[string]any{"download": true}, Precheck: a.recentAuth(r),
	}, func(ctx context.Context) error {
		dir, rm, err := store.NewTempDir(a.backupDir, store.BackupTempPrefix)
		if err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		remove = rm
		path = filepath.Join(dir, name)
		return a.backup(ctx, path, body.Passphrase)
	})
	if err != nil {
		// A backup whose outcome could not be audited is not handed out, as
		// `hearth backup` removes it.
		if errors.Is(err, policy.ErrOutcomeNotRecorded) {
			err = fmt.Errorf("the backup was made but its audit outcome was not recorded: %w", err)
		}
		a.writeActionError(w, r, "make the backup", err)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		a.writeActionError(w, r, "make the backup", err)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		a.writeActionError(w, r, "make the backup", err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil && ctx.Err() == nil {
		a.log.WarnContext(ctx, "backup download interrupted", "file", name, "err", err)
	}
}
