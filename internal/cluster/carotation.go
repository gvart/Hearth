// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// Files of this hub's node certificate of the new CA, in the cluster dir.
const (
	nextNodeCertFile = "node.next.crt"
	nextNodeKeyFile  = "node.next.key"
)

// Timing of the rotation.
const (
	// caMemberWait bounds how long FinishCA waits for every hub to reach
	// a stage.
	caMemberWait = 2 * time.Minute
	// caGoneGrace is how long a member must stay down before FinishCA
	// gives up on it rather than waits.
	caGoneGrace = 5 * time.Second
	// caInfoTimeout bounds one CAInfo or FetchCAKey call.
	caInfoTimeout = 5 * time.Second
)

// Errors of the rotation.
var (
	// errRotationViaLog refuses the rotation's commands through Apply,
	// ApplyOrForward, Forward and the control socket.
	errRotationViaLog = errors.New("hub CA rotation commands are proposed only by `hearth cluster ca`")
	// ErrUnpinnedCerts refuses a rotation while a certificate it could not
	// renew safely is in use, unless the operator accepts that.
	ErrUnpinnedCerts = errors.New("certificates a rotation cannot renew safely")
	// ErrOldCAHolders refuses to finish a rotation while an agent or hub
	// still holds only old-CA certificates, unless forced.
	ErrOldCAHolders = errors.New("agents or hubs would be cut off")
	// ErrNoRotation is returned when finishing with no rotation under way.
	ErrNoRotation = errors.New("no hub CA rotation is under way")
	// errNotPinned refuses an old-CA hub certificate other than the one
	// pinned for its hub during a rotation.
	errNotPinned = errors.New("not the hub certificate pinned for this rotation")
)

// isRotationCommand reports whether cmd is a command only the rotation
// proposes.
func isRotationCommand(cmd store.Command) bool {
	switch cmd.(type) {
	case store.StartCARotation, store.AdvanceCARotation, store.ResealSecrets:
		return true
	}
	return false
}

// Resealer returns the secrets among secrets that are not sealed with the
// newest CA key yet, each with Resealed set to it sealed with that key. It
// fails if any secret cannot be opened.
type Resealer func(ctx context.Context, secrets []store.SealedSecret) ([]store.SealedSecret, error)

// RotateOptions are the options of RotateCA.
type RotateOptions struct {
	// AcceptUnpinned starts the rotation although some certificates have
	// no pinned fingerprint or a recorded mismatch: their holders are not
	// renewed and are cut off when the rotation finishes. It never covers a
	// hub presenting a certificate without a recorded fingerprint.
	AcceptUnpinned bool
	// DryRun checks and plans, and changes nothing.
	DryRun bool
}

// RotatePlan is what RotateCA did or would do.
type RotatePlan struct {
	// NewCAFP is the new CA's fingerprint; empty for a dry run.
	NewCAFP string
	// Pins are the node certificate fingerprints pinned per hub.
	Pins map[string]string
	// Unpinned are the certificates the rotation cannot renew.
	Unpinned []store.UnpinnedCert
}

// AbortOptions are the options of AbortCA.
type AbortOptions struct {
	// DryRun checks and plans, and changes nothing.
	DryRun bool
}

// AbortPlan is what AbortCA did or would do.
type AbortPlan struct {
	NewCAFP string
	// RenewedDevices were handed a certificate of the new CA: the abort
	// cuts them off, and they enroll again.
	RenewedDevices []string
}

func describeUnpinned(certs []store.UnpinnedCert) string {
	parts := make([]string, 0, len(certs))
	for _, c := range certs {
		why := "no recorded fingerprint"
		if c.Mismatch {
			why = "another certificate was presented with its serial"
		}
		parts = append(parts, fmt.Sprintf("%s %s (serial %s: %s)", c.Kind, c.ID, c.Serial, why))
	}
	return strings.Join(parts, ", ")
}

// CAInfo is a hub's side of a rotation.
type CAInfo struct {
	ServingFP   string
	NextFP      string
	HasNextKey  bool
	HasNextCert bool
	CutOver     bool
}

// CAStatus is the state of the latest rotation and each hub's side of it.
type CAStatus struct {
	// Rotation is the latest rotation; nil when there has been none.
	Rotation *store.CARotation
	Hubs     []HubCAInfo
	// OldDevices are the devices still on the old CA during a rotation.
	OldDevices []string
}

// HubCAInfo is one hub's side of a rotation, or why it is unknown.
type HubCAInfo struct {
	ID    string
	Info  CAInfo
	Error string `json:",omitempty"`
}

// FinishOptions are the options of FinishCA.
type FinishOptions struct {
	// Force finishes although agents or hubs still hold only old-CA
	// certificates: they are cut off.
	Force bool
	// DryRun checks and plans, and changes nothing.
	DryRun bool
}

// FinishPlan is what FinishCA did or would do.
type FinishPlan struct {
	NewCAFP string
	// OldDevices and OldHubs still hold only old-CA certificates: the
	// finish cuts them off.
	OldDevices []string
	OldHubs    []string
	// Resealed counts the secrets re-sealed with the new CA's key.
	Resealed int
}

func describeOld(devices, hubs []string) string {
	var parts []string
	if len(devices) > 0 {
		parts = append(parts, "devices "+strings.Join(devices, ", "))
	}
	if len(hubs) > 0 {
		parts = append(parts, "hubs "+strings.Join(hubs, ", "))
	}
	return strings.Join(parts, "; ")
}

// checkNextNodeCert checks der, a node certificate of ca's next CA received
// for key: hub id's, in cluster epoch epoch.
func checkNextNodeCert(ca *pki.CA, der []byte, key crypto.Signer, id, epoch string) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	next := ca.Next()
	if next == nil || cert.CheckSignatureFrom(next) != nil {
		return nil, errors.New("not signed by the new CA")
	}
	if got, err := pki.HubNodeID(cert); err != nil || got != id {
		return nil, errors.New("issued to another hub")
	}
	if pki.HubEpoch(cert) != epoch {
		return nil, errOtherEpoch
	}
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return nil, errors.New("issued for another key")
	}
	return cert, nil
}

// writeNextNodeCert writes a hub's node certificate of the new CA and its
// key into dir, its cluster dir.
func writeNextNodeCert(dir string, cert *x509.Certificate, key any) (*tls.Certificate, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode node key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	certPEM := pki.EncodeCertPEM(cert)
	if err := writeFileSync(filepath.Join(dir, nextNodeKeyFile), keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileSync(filepath.Join(dir, nextNodeCertFile), certPEM, 0o644); err != nil {
		return nil, err
	}
	tc, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tc, nil
}

// readNextNodeCert reads a hub's node certificate of the new CA from dir,
// its cluster dir; nil if there is none.
func readNextNodeCert(dir string) (*tls.Certificate, error) {
	tc, err := tls.LoadX509KeyPair(filepath.Join(dir, nextNodeCertFile), filepath.Join(dir, nextNodeKeyFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("load the node certificate of the new hub CA: %w", err)
	}
	if tc.Leaf == nil {
		if tc.Leaf, err = x509.ParseCertificate(tc.Certificate[0]); err != nil {
			return nil, fmt.Errorf("load the node certificate of the new hub CA: %w", err)
		}
	}
	return &tc, nil
}

// errMissedRotation stops a hub that a hub CA rotation finished without: it
// lacks the new CA's key, or a node certificate of it.
var errMissedRotation = errors.New("the hub CA rotation finished without this hub: it holds no key and no " +
	"node certificate of the new CA; remove it (`hearth cluster remove`), wipe its data dir and join it again")

// recoverNodeCertFinish moves the node certificate of the new CA over the
// node certificate once the rotation finished on this hub (the CA trusts no
// next CA, and the new CA issued it). It completes a move a crash
// interrupted: the key is moved first, then the certificate.
func recoverNodeCertFinish(dir string, ca *pki.CA) error {
	certPath := filepath.Join(dir, nextNodeCertFile)
	b, err := os.ReadFile(certPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	cert, err := pki.ParseCertPEM(b)
	if err != nil {
		return fmt.Errorf("read %s: %w", nextNodeCertFile, err)
	}
	if ca.Next() != nil || cert.CheckSignatureFrom(ca.Cert()) != nil {
		return nil // the rotation has not finished here
	}
	keyPath := filepath.Join(dir, nextNodeKeyFile)
	if err := os.Rename(keyPath, filepath.Join(dir, nodeKeyFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(certPath, filepath.Join(dir, nodeCertFile)); err != nil {
		return err
	}
	syncDirOf(dir)
	return nil
}

// writeFileSync replaces path with data, mode perm, through a temporary file
// that reaches the disk before the rename. A temporary file left by a crash
// is removed first, so the new one is created with perm.
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	syncDirOf(filepath.Dir(path))
	return nil
}

func syncDirOf(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
