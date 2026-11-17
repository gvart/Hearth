// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
	"github.com/gvart/hearth/internal/store"
)

const maxHostnameLen = 253

// Enroller implements agentv1connect.EnrollServiceHandler.
type Enroller struct {
	store  *store.Store
	ca     *pki.CA
	policy *policy.Engine
	log    *slog.Logger
	// leadership: only the cluster leader enrolls devices.
	leadership Leadership
	now        func() time.Time
}

var _ agentv1connect.EnrollServiceHandler = (*Enroller)(nil)

// NewEnroller returns an EnrollService handler.
func NewEnroller(st *store.Store, ca *pki.CA, pol *policy.Engine, log *slog.Logger) *Enroller {
	return &Enroller{store: st, ca: ca, policy: pol, log: log, leadership: soloLeadership{}, now: time.Now}
}

// Enroll consumes a token and issues a client certificate for a new device.
// A hub that is not the cluster leader refuses with a NotLeader detail.
func (e *Enroller) Enroll(ctx context.Context, req *connect.Request[agentv1.EnrollRequest]) (*connect.Response[agentv1.EnrollResponse], error) {
	if !e.leadership.IsLeader() {
		return nil, notLeaderError(e.leadership)
	}
	msg := req.Msg
	if msg.GetTokenSecret() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("token is required"))
	}
	if len(msg.GetHostname()) > maxHostnameLen {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("hostname too long"))
	}
	deviceID, err := pki.NewDeviceID()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	var cert *x509.Certificate
	err = e.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorToken,
		ActorID:   tokenActorID(msg.GetTokenSecret()),
		Action:    policy.DeviceEnroll,
		Target:    deviceID,
		Detail:    map[string]any{"hostname": msg.GetHostname()},
	}, func(ctx context.Context) error {
		now := e.now()
		// Sign first: a malformed CSR must not burn the token.
		c, err := e.ca.SignClientCSR(msg.GetCsr(), deviceID, now)
		if err != nil {
			return errBadCSR{err}
		}
		labels, err := e.store.Tokens().Consume(ctx, msg.GetTokenSecret(), now)
		if err != nil {
			return err
		}
		if err := e.store.Devices().Upsert(ctx, store.Device{
			ID: deviceID, Name: msg.GetHostname(), Hostname: msg.GetHostname(),
			Labels: labels, FirstSeen: now, LastSeen: now, Status: "unknown",
		}); err != nil {
			return err
		}
		if err := e.store.Certs().Create(ctx, pki.SerialString(c), deviceID); err != nil {
			return err
		}
		cert = c
		return nil
	})
	if err != nil {
		return nil, e.toConnectError(ctx, err)
	}

	e.log.InfoContext(ctx, "device enrolled", "device_id", deviceID, "hostname", msg.GetHostname())
	return connect.NewResponse(&agentv1.EnrollResponse{
		DeviceId:      deviceID,
		Certificate:   cert.Raw,
		CaCertificate: e.ca.Cert().Raw,
	}), nil
}

type errBadCSR struct{ err error }

func (e errBadCSR) Error() string { return e.err.Error() }
func (e errBadCSR) Unwrap() error { return e.err }

func (e *Enroller) toConnectError(ctx context.Context, err error) error {
	var bad errBadCSR
	switch {
	case errors.As(err, &bad):
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid CSR: %w", bad.err))
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeUnauthenticated, errors.New("unknown enrollment token"))
	case errors.Is(err, store.ErrTokenUsed):
		return connect.NewError(connect.CodeUnauthenticated, errors.New("enrollment token already used"))
	case errors.Is(err, store.ErrTokenExpired):
		return connect.NewError(connect.CodeUnauthenticated, errors.New("enrollment token expired"))
	case errors.Is(err, policy.ErrDenied):
		return connect.NewError(connect.CodePermissionDenied, errors.New("enrollment denied by policy"))
	default:
		e.log.ErrorContext(ctx, "enrollment failed", "err", err)
		return connect.NewError(connect.CodeInternal, errors.New("enrollment failed"))
	}
}

// tokenActorID is a short, non-reversible handle for a token in the audit log,
// so attempts with the same token can be correlated without storing the secret.
func tokenActorID(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:6])
}
