// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/store"
)

// errNoNextKey is FetchCAKey's answer from a hub without the new CA's key.
var errNoNextKey = errors.New("this hub does not hold the new CA's key")

// FetchCAKey hands a member the new CA's key during a rotation and, on the
// leader, issues and records its node certificate of the new CA (see
// Node.RotateCA). The caller must be a member presenting its pinned node
// certificate, or one of the new CA. Every request is decided by policy and
// audited, refusals before the decision included.
func (s *JoinServer) FetchCAKey(ctx context.Context, req *connect.Request[clusterv1.FetchCAKeyRequest]) (*connect.Response[clusterv1.FetchCAKeyResponse], error) {
	id, err := s.memberPeer(ctx)
	if err != nil {
		s.auditFetchRefused(ctx, err)
		return nil, err
	}
	var keyDER, certDER []byte
	err = s.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorHub,
		ActorID:   id,
		Action:    policy.ClusterCAFetchKey,
		Target:    id,
		Detail:    map[string]any{"new_ca": req.Msg.GetNewCaFingerprint(), "certificate": len(req.Msg.GetCsr()) > 0},
	}, func(ctx context.Context) error {
		rot, err := s.store.CARotations().Active(ctx)
		if err != nil {
			return err
		}
		next := s.ca.Next()
		switch {
		case rot.NewCAFP != req.Msg.GetNewCaFingerprint():
			return store.ErrNotFound
		case next == nil || pki.FingerprintHex(next) != rot.NewCAFP || !s.ca.HasNextKey():
			return errNoNextKey
		}
		if keyDER, err = s.ca.NextKeyDER(); err != nil {
			return err
		}
		if len(req.Msg.GetCsr()) > 0 && s.node.IsLeader() {
			cert, err := s.node.issueNextNodeCert(ctx, req.Msg.GetCsr(), id)
			if err != nil {
				return err
			}
			certDER = cert.Raw
		}
		return nil
	})
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no such hub CA rotation is under way"))
	case errors.Is(err, errNoNextKey):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, policy.ErrDenied):
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fetching the CA key denied by policy"))
	default:
		s.log.ErrorContext(ctx, "hand out the new hub CA key", "to", id, "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("fetching the CA key failed"))
	}
	s.log.InfoContext(ctx, "handed the new hub CA key to a member", "to", id, "certificate", len(certDER) > 0)
	return connect.NewResponse(&clusterv1.FetchCAKeyResponse{CaKey: keyDER, Certificate: certDER}), nil
}

// fetchRefusalEvery bounds the audit entries of refused FetchCAKey calls:
// one per caller per interval, which counts the refusals it left out.
const fetchRefusalEvery = time.Minute

// fetchRefusals rate-limits the audit entries of refused FetchCAKey calls.
type fetchRefusals struct {
	mu   sync.Mutex
	last map[string]refusalWindow
}

type refusalWindow struct {
	at         time.Time
	suppressed int
}

// admit reports whether a refusal of caller at now gets an audit entry and,
// if so, how many refusals of it were left out since the last entry.
func (f *fetchRefusals) admit(caller string, now time.Time) (bool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.last == nil {
		f.last = map[string]refusalWindow{}
	}
	if w, ok := f.last[caller]; ok && now.Sub(w.at) < fetchRefusalEvery {
		w.suppressed++
		f.last[caller] = w
		return false, 0
	}
	if len(f.last) >= 256 {
		for k, w := range f.last {
			if now.Sub(w.at) >= fetchRefusalEvery {
				delete(f.last, k)
			}
		}
	}
	suppressed := f.last[caller].suppressed
	f.last[caller] = refusalWindow{at: now}
	return true, suppressed
}

// auditFetchRefused records a FetchCAKey refused before its policy decision,
// such as a certificate minted with the old CA key: nobody but a pinned hub
// may get the new key, and attempts are on record, at most one entry per
// caller a minute, with the count of those left out.
func (s *JoinServer) auditFetchRefused(ctx context.Context, refusal error) {
	actor := "unknown"
	detail := map[string]any{"reason": refusal.Error()}
	if cs, _ := ctx.Value(tlsStateKey{}).(*tls.ConnectionState); cs != nil && len(cs.PeerCertificates) > 0 {
		c := cs.PeerCertificates[0]
		if id, err := pki.HubNodeID(c); err == nil {
			actor = id
		}
		detail["serial"], detail["fingerprint"] = pki.SerialString(c), pki.FingerprintHex(c)
	}
	ok, suppressed := s.fetchRefused.admit(actor, s.now())
	if !ok {
		return
	}
	if suppressed > 0 {
		detail["refusals_not_audited_before"] = suppressed
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return
	}
	if _, err := s.store.Audit().Append(ctx, store.AuditEntry{
		TS: s.now(), ActorKind: policy.ActorHub, ActorID: actor, Action: string(policy.ClusterCAFetchKey),
		Target: actor, Decision: policy.Deny, Result: "refused: " + refusal.Error(), Detail: b,
	}); err != nil {
		s.log.ErrorContext(ctx, "audit a refused CA key fetch", "err", err)
	}
}

// CAInfo reports this hub's side of a rotation to a member.
func (s *JoinServer) CAInfo(ctx context.Context, _ *connect.Request[clusterv1.CAInfoRequest]) (*connect.Response[clusterv1.CAInfoResponse], error) {
	if _, err := s.memberPeer(ctx); err != nil {
		return nil, err
	}
	i := s.node.localCAInfo()
	return connect.NewResponse(&clusterv1.CAInfoResponse{
		ServingCaFingerprint: i.ServingFP, NextCaFingerprint: i.NextFP, HasNextKey: i.HasNextKey,
		HasNextNodeCertificate: i.HasNextCert, CutOver: i.CutOver,
	}), nil
}
