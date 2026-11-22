// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gvart/hearth/internal/pki"
)

// JoinFileName is the join file in a hub data dir: `hearth agent join
// --hub-data-dir` writes it when the hub minted this device a join token,
// and `hearth hub --join-file` joins with it (#328).
const JoinFileName = "join"

// JoinFile is the join a device was handed at its enrollment: the master to
// join through and the join token. The token is a secret: the file is 0600.
type JoinFile struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

// WriteJoinFile writes j at path, 0600, creating its directory (0700).
func WriteJoinFile(path string, j JoinFile) error {
	if j.URL == "" || j.Token == "" {
		return errors.New("write join file: no URL or token")
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("write join file: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write join file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("write join file: %w", err)
	}
	return nil
}

// ReadJoinFile reads the join file at path. A missing file is an error
// matching os.ErrNotExist.
func ReadJoinFile(path string) (JoinFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return JoinFile{}, err
	}
	var j JoinFile
	if err := json.Unmarshal(b, &j); err != nil || j.URL == "" || j.Token == "" {
		return JoinFile{}, fmt.Errorf("join file %s is not a join: delete it and install with a new command", path)
	}
	return j, nil
}

// ClearPartialJoin deletes what a join that stopped half way left in
// dataDir: Join writes the CA certificate last, so a node certificate or a
// CA key without it means the hub never joined. It reports whether there
// was any.
func ClearPartialJoin(dataDir string) (bool, error) {
	if _, err := os.Stat(filepath.Join(dataDir, pki.CACertFile)); err == nil {
		return false, nil
	}
	found := false
	for _, f := range []string{
		filepath.Join(dataDir, StateDir, nodeCertFile), filepath.Join(dataDir, StateDir, nodeKeyFile),
		filepath.Join(dataDir, StateDir, rolesFile), filepath.Join(dataDir, StateDir, seedsFile),
		filepath.Join(dataDir, EpochFile), filepath.Join(dataDir, pki.CAKeyFile),
	} {
		err := os.Remove(f)
		switch {
		case err == nil:
			found = true
		case !errors.Is(err, os.ErrNotExist):
			return found, fmt.Errorf("clear a partial join: %w", err)
		}
	}
	return found, nil
}
