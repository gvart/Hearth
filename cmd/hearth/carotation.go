// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/integrations/proxmox"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// runbookSealInfo names the key that seals runbook runs' copies of their file.
const runbookSealInfo = "hearth runbook run seal v1"

// newServerCert returns the hub's server certificate, issued again by the CA
// the hub serves whenever a hub CA rotation changes it.
func newServerCert(ctx context.Context, ca *pki.CA, hosts []string, epoch string, log *slog.Logger) (*atomic.Pointer[tls.Certificate], error) {
	var p atomic.Pointer[tls.Certificate]
	issue := func() error {
		c, err := ca.IssueHubServerCert(hosts, epoch, time.Now())
		if err != nil {
			return err
		}
		p.Store(&c)
		return nil
	}
	if err := issue(); err != nil {
		return nil, err
	}
	ca.OnChange(func() {
		if err := issue(); err != nil {
			log.ErrorContext(ctx, "issue the server certificate for the hub CA", "err", err)
		}
	})
	return &p, nil
}

// hubSealers seal secrets in the store with keys derived from the hub CA
// key, which every hub of a cluster holds: kubeconfigs, Proxmox connections
// and runbook runs' files. During a hub CA rotation they open with either
// CA's key and seal with the one the hub serves.
type hubSealers struct {
	kube, proxmox, runbook *kubernetes.Sealer
}

func newHubSealers(ctx context.Context, ca *pki.CA, log *slog.Logger) (*hubSealers, error) {
	keys, err := ca.KeyDERs()
	if err != nil {
		return nil, err
	}
	var s hubSealers
	if s.kube, err = kubernetes.NewSealer(keys[0]); err != nil {
		return nil, err
	}
	if s.proxmox, err = kubernetes.NewPurposeSealer(keys[0], proxmox.SealInfo); err != nil {
		return nil, err
	}
	if s.runbook, err = kubernetes.NewPurposeSealer(keys[0], runbookSealInfo); err != nil {
		return nil, err
	}
	if err := s.rekey(keys); err != nil {
		return nil, err
	}
	ca.OnChange(func() {
		keys, err := ca.KeyDERs()
		if err == nil {
			err = s.rekey(keys)
		}
		if err != nil {
			log.ErrorContext(ctx, "rekey the sealers for the hub CA", "err", err)
		}
	})
	return &s, nil
}

func (s *hubSealers) rekey(keys [][]byte) error {
	for _, sealer := range []*kubernetes.Sealer{s.kube, s.proxmox, s.runbook} {
		if err := sealer.SetSecrets(keys...); err != nil {
			return err
		}
	}
	return nil
}

// reseal is the cluster's Resealer: it returns the secrets not sealed with
// the serving CA's key, sealed with it.
func (s *hubSealers) reseal(_ context.Context, secrets []store.SealedSecret) ([]store.SealedSecret, error) {
	var stale []store.SealedSecret
	for _, sec := range secrets {
		sealer, id := s.kube, sec.ID
		switch sec.Table {
		case store.SealedProxmoxServers:
			sealer = s.proxmox
		case store.SealedRunbookRuns:
			sealer, id = s.runbook, automation.RunbookSealID(sec.ID)
		}
		out, changed, err := sealer.Reseal(id, sec.Sealed)
		if err != nil {
			return nil, fmt.Errorf("re-seal %s %s: %w", sec.Table, sec.ID, err)
		}
		if changed {
			sec.Resealed = out
			stale = append(stale, sec)
		}
	}
	return stale, nil
}
