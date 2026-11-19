// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// A cluster epoch separates a cluster restored from a backup from the cluster
// it came from. The two share a CA, and a backup cannot know the hubs that
// joined after it, so a certificate from the CA does not tell them apart.
//
// A restore writes a new random epoch to EpochFile. The first node certificate
// of the restored hub carries it, every hub that joins gets it from the hub
// that signs its certificate and keeps it in EpochFile too, and a renewed
// certificate keeps it. A restored cluster refuses to admit a binary that does
// not know epochs, since it could not serve as leader. Hubs compare
// epochs on the Raft transport and on hub-to-hub calls, in both directions. A
// cluster that was never restored has no epoch, so nothing changes for it.
//
// This keeps out hubs that are merely out of date. It does not stop a hostile
// one: every voter of the old cluster holds the CA key.

// EpochFile holds the epoch a restore started, in the hub's data dir.
const EpochFile = "cluster-epoch"

const epochBytes = 16

// errOtherEpoch refuses a hub of another cluster epoch. It matches
// store.ErrCertRevoked, so every path that refuses a revoked hub refuses it too.
var errOtherEpoch = fmt.Errorf("hub of another cluster epoch: %w", store.ErrCertRevoked)

// WriteNewEpoch writes a new random epoch to EpochFile in dir.
func WriteNewEpoch(dir string) error {
	b := make([]byte, epochBytes)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("new cluster epoch: %w", err)
	}
	return writeEpoch(dir, hex.EncodeToString(b))
}

func writeEpoch(dir, epoch string) error {
	if err := os.WriteFile(filepath.Join(dir, EpochFile), []byte(epoch+"\n"), 0o600); err != nil {
		return fmt.Errorf("write cluster epoch: %w", err)
	}
	return nil
}

// readEpoch returns the epoch in dataDir's EpochFile, or "" without one.
func readEpoch(dataDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, EpochFile))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read cluster epoch: %w", err)
	}
	epoch := strings.TrimSpace(string(b))
	if raw, err := hex.DecodeString(epoch); err != nil || len(raw) != epochBytes {
		return "", fmt.Errorf("read cluster epoch: %s is malformed", EpochFile)
	}
	return epoch, nil
}

// requireEpoch refuses a hub whose TLS certificate is of another epoch, on the
// client side of a hub-to-hub call. It runs after the standard verification.
func requireEpoch(epoch string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || pki.HubEpoch(cs.PeerCertificates[0]) != epoch {
			return errOtherEpoch
		}
		return nil
	}
}

// Epoch is this node's cluster epoch. It is empty before Start, and for a
// cluster that was never restored from a backup.
func (n *Node) Epoch() string { return n.epoch }
