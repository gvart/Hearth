// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

type tlsStateKey struct{}

// Errors that map to specific codes.
var (
	errSchema    = errors.New("schema mismatch")
	errNodeTaken = errors.New("node ID already in the cluster")
	errBadCSR    = errors.New("invalid CSR")
)

// tokenActorID is a short, non-reversible handle for a token in the audit log.
func tokenActorID(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:6])
}

// JoinParams describes a hub joining a cluster.
type JoinParams struct {
	// URL is the TLS listener of the master that issued the token, e.g.
	// https://hub-a:7443.
	URL string
	// Token is the encoded join token (hearthj1.<secret>.<fingerprint>).
	Token string
	// DataDir is the joining hub's data dir. It must not hold a CA yet.
	DataDir string
	// NodeID and Address (its --cluster-advertise) identify the joining hub
	// to its peers.
	NodeID  string
	Address string
	// MaxSchema is the newest store schema the joining binary supports;
	// zero means store.SchemaVersion(). Tests set it to stand in for
	// another binary.
	MaxSchema int64
	// AllowedRoles are this host's --allow-roles, sent to an AP cluster:
	// only a host that allows master receives the CA key.
	AllowedRoles RoleSet
}

// Join admits this hub into a cluster: it pins the cluster's CA by the
// token's fingerprint, sends a CSR and receives a node certificate and the
// CA, key included for a host that allows the master role, which it writes
// into DataDir (ca.key at 0600).
func Join(ctx context.Context, p JoinParams) error {
	tok, err := pki.ParseJoinToken(p.Token)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(p.DataDir, pki.CAKeyFile)); err == nil {
		return fmt.Errorf("%s already holds a hub CA; --join needs a fresh data dir", p.DataDir)
	}
	dir := filepath.Join(p.DataDir, StateDir)
	if _, err := os.Stat(filepath.Join(dir, nodeCertFile)); err == nil {
		return fmt.Errorf("%s already holds a node certificate; --join needs a fresh data dir", p.DataDir)
	}
	key, err := pki.NewKey()
	if err != nil {
		return err
	}
	csr, err := pki.NewCSR(key, p.NodeID)
	if err != nil {
		return err
	}
	if p.MaxSchema == 0 {
		p.MaxSchema = store.SchemaVersion()
	}
	req := &clusterv1.JoinRequest{
		TokenSecret:   tok.Secret,
		NodeId:        p.NodeID,
		Address:       p.Address,
		Csr:           csr,
		SchemaVersion: p.MaxSchema,
		AllowedRoles:  p.AllowedRoles.Strings(),
	}
	u, err := url.Parse(p.URL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid hub URL %q", p.URL)
	}
	transport := &http.Transport{TLSClientConfig: pki.PinnedTLSConfig(tok.CAFingerprint, u.Hostname())}
	defer transport.CloseIdleConnections()
	client := clusterv1connect.NewClusterServiceClient(&http.Client{Transport: transport}, u.String())
	resp, err := client.Join(ctx, connect.NewRequest(req))
	if err != nil {
		return fmt.Errorf("join cluster at %s: %w", p.URL, err)
	}
	if len(resp.Msg.GetCaKey()) == 0 && p.AllowedRoles.Has(RoleMaster) {
		// Only a master holds the CA key; one allowing the master role gets it.
		return errors.New("join: the cluster sent no CA key, though this host allows the master role")
	}
	cert, err := x509.ParseCertificate(resp.Msg.GetCertificate())
	if err != nil {
		return fmt.Errorf("join: parse node certificate: %w", err)
	}
	if id, err := pki.HubNodeID(cert); err != nil || id != p.NodeID {
		return errors.New("join: node certificate does not carry this node's ID")
	}
	if err := writeNodeCert(dir, cert, key); err != nil {
		return fmt.Errorf("join: %w", err)
	}
	// Kept apart from the certificate, so a hub that loses it stays in the epoch.
	if epoch := pki.HubEpoch(cert); epoch != "" {
		if err := writeEpoch(p.DataDir, epoch); err != nil {
			return fmt.Errorf("join: %w", err)
		}
	}
	if len(resp.Msg.GetCaKey()) == 0 {
		// A member that is no master holds the CA certificate only.
		if err := pki.InstallCACert(p.DataDir, resp.Msg.GetCaCertificate(), tok.CAFingerprint); err != nil {
			return fmt.Errorf("join: %w", err)
		}
		return nil
	}
	if err := pki.InstallCA(p.DataDir, resp.Msg.GetCaCertificate(), resp.Msg.GetCaKey(), tok.CAFingerprint); err != nil {
		return fmt.Errorf("join: %w", err)
	}
	return nil
}
