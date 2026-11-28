// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// auditKeySealInfo names the key that seals the audit MAC keys of earlier hub
// CAs in the store (#387).
const auditKeySealInfo = "hearth audit key seal v1"

// auditKeySyncInterval is how often a master checks that the store holds,
// sealed, the audit key of every hub CA key it holds.
const auditKeySyncInterval = 5 * time.Minute

// auditKeySealID binds a sealed audit key to its key id.
func auditKeySealID(kid string) string { return "audit-key/" + kid }

// syncAuditKeys stores, sealed, the audit key of each hub CA key the master
// holds that the store lacks, and gives ring the earlier ones the store
// holds: once a rotation finished and the old CA key is gone, the entries
// sealed with it still verify, here and on a master that joins later.
func syncAuditKeys(ctx context.Context, st *store.Store, ring *pki.AuditKeyring, sealer *kubernetes.Sealer, now time.Time) error {
	stored, err := st.AuditKeys().List(ctx)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	var earlier []pki.AuditKey
	var errs []error
	for _, k := range stored {
		have[k.ID] = true
		key, err := sealer.Open(auditKeySealID(k.ID), k.Sealed)
		if err != nil {
			errs = append(errs, fmt.Errorf("open audit key %s: %w", k.ID, err))
			continue
		}
		earlier = append(earlier, pki.AuditKey{ID: k.ID, Key: key})
	}
	ring.AddEarlier(earlier...)
	for _, k := range ring.Held() {
		if have[k.ID] {
			continue
		}
		sealed, err := sealer.Seal(auditKeySealID(k.ID), k.Key)
		if err == nil {
			err = st.AuditKeys().Put(ctx, k.ID, sealed, now)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("store audit key %s: %w", k.ID, err))
		}
	}
	return errors.Join(errs...)
}

// runAuditKeys runs syncAuditKeys now, whenever the hub CA changes, and every
// auditKeySyncInterval, until ctx ends.
func runAuditKeys(ctx context.Context, st *store.Store, ca *pki.CA, ring *pki.AuditKeyring, sealer *kubernetes.Sealer, log *slog.Logger) error {
	wake := make(chan struct{}, 1)
	ca.OnChange(func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	})
	failed := 0
	for {
		wait := auditKeySyncInterval
		if err := syncAuditKeys(ctx, st, ring, sealer, time.Now()); err != nil && ctx.Err() == nil {
			// Until the masters compared their rows, or while no master
			// takes the write: soon again, and said once it lasts.
			failed++
			wait = auditKeyRetry
			if failed == 10 {
				log.WarnContext(ctx, "the audit keys of the hub CA are not stored: entries sealed before a CA rotation "+
					"may not verify after it", "err", err)
			}
		} else {
			failed = 0
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-wake:
		case <-t.C:
		}
		t.Stop()
	}
}

// auditKeyRetry is how soon a sync that failed is tried again.
const auditKeyRetry = 15 * time.Second
