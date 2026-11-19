// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"log/slog"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// Agents during a hub CA rotation (docs/cluster.md, "Rotating the hub CA").
// The leader renews an agent on its next connection: the Welcome carries a
// client certificate of the new CA for the key the agent connected with, and
// the CAs to trust. Only a certificate whose exact fingerprint was recorded
// before the rotation is renewed.

// rotationReader is the part of store.CARotations the agent stream needs.
type rotationReader interface {
	Latest(ctx context.Context) (store.CARotation, error)
}

// certRecorder is the part of store.Certs that records a renewed certificate.
type certRecorder interface {
	Record(ctx context.Context, c store.CertRecord) error
}

// issuerFP is the fingerprint of the CA that issued cert, which ca trusts.
func issuerFP(ca *pki.CA, cert *x509.Certificate) string {
	if issuer := ca.IssuerOf(cert); issuer != nil {
		return pki.FingerprintHex(issuer)
	}
	return ""
}

// activeRotation returns the hub CA rotation under way, if any.
func (s *AgentStream) activeRotation(ctx context.Context) (store.CARotation, bool) {
	if s.rotations == nil {
		return store.CARotation{}, false
	}
	rot, err := s.rotations.Latest(ctx)
	return rot, err == nil && rot.Active()
}

// renewal returns what the Welcome carries for a hub CA rotation: a client
// certificate of the new CA, PEM, when the agent connected with exactly the
// old-CA certificate recorded for it, and the CAs to trust, PEM: during a
// rotation only with that certificate (an agent adds a CA only with a
// certificate of it), after one always. Both are nil otherwise.
func (s *AgentStream) renewal(ctx context.Context, log *slog.Logger, deviceID string) (cert, bundle []byte) {
	if s.ca == nil || s.rotations == nil {
		return nil, nil
	}
	rot, err := s.rotations.Latest(ctx)
	if err != nil {
		return nil, nil
	}
	var b bytes.Buffer
	for _, c := range s.ca.TrustedCerts() {
		b.Write(pki.EncodeCertPEM(c))
	}
	bundle = b.Bytes()
	if !rot.Active() {
		return nil, bundle
	}
	chain, ok := chainFrom(ctx)
	serial, hasSerial := serialFrom(ctx)
	if !ok || !hasSerial || s.pins == nil || s.renew == nil ||
		!s.ca.HasNextKey() || pki.FingerprintHex(s.ca.SignerCert()) != rot.NewCAFP {
		return nil, nil
	}
	leaf := chain[0]
	if issuerFP(s.ca, leaf) == rot.NewCAFP {
		return nil, nil // renewed already
	}
	if s.authority() != nil {
		return nil, nil
	}
	recorded, err := s.pins.Fingerprint(ctx, serial, deviceID)
	if err != nil || recorded != pki.FingerprintHex(leaf) {
		log.WarnContext(ctx, "agent certificate not renewed for the hub CA rotation: it is not the certificate "+
			"recorded for its serial; the device must enroll again once the rotation finishes", "serial", serial)
		return nil, nil
	}
	c, err := s.ca.SignClientKey(leaf.PublicKey, deviceID, s.now())
	if err != nil {
		log.ErrorContext(ctx, "renew the agent certificate", "err", err)
		return nil, nil
	}
	// Recorded without a fingerprint: the agent pins it when it connects
	// with it, which is what counts as having moved to the new CA.
	if err := s.renew.Record(ctx, store.CertRecord{
		Serial: pki.SerialString(c), DeviceID: deviceID, CAFP: rot.NewCAFP,
	}); err != nil {
		log.ErrorContext(ctx, "record the renewed agent certificate", "err", err)
		return nil, nil
	}
	log.InfoContext(ctx, "renewed the agent certificate from the new hub CA", "serial", pki.SerialString(c))
	return pki.EncodeCertPEM(c), bundle
}

// rotationState names the latest hub CA rotation and its stage, or is empty;
// ok is false when the store could not tell.
// A stream whose Welcome saw another state is ended on its next heartbeat,
// so that the agent reconnects and its Welcome carries the renewal and the
// CAs to trust: agents connected when a rotation starts renew without a hub
// restart, and drop the old CA once it finishes. Whether this hub can sign
// with the new CA is part of it: a hub that fetches the key after the start
// renews the agents connected to it then.
func (s *AgentStream) rotationState(ctx context.Context) (string, bool) {
	if s.rotations == nil {
		return "", true
	}
	rot, err := s.rotations.Latest(ctx)
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrSchemaTooOld) {
		return "", true
	} else if err != nil {
		return "", false // unknown: checked again on the next heartbeat
	}
	state := rot.NewCAFP + "/" + rot.Stage
	if s.ca != nil && s.ca.HasNextKey() && pki.FingerprintHex(s.ca.SignerCert()) == rot.NewCAFP {
		state += "/signs"
	}
	return state, true
}

// errRotationMoved ends a stream to hand the agent what a hub CA rotation
// changed; the agent reconnects at once.
var errRotationMoved = connect.NewError(connect.CodeUnavailable,
	errors.New("the hub CA rotation moved on: reconnect"))

// errUntrustedCA ends a stream whose client certificate is of a CA the hub
// no longer trusts: one opened before a hub CA rotation finished.
var errUntrustedCA = connect.NewError(connect.CodeUnauthenticated,
	errors.New("client certificate of a hub CA no longer trusted: enroll again"))

// trustedLeaf reports whether ca, when set, still trusts the CA that issued
// the certificate in ctx.
func trustedLeaf(ctx context.Context, ca *pki.CA) bool {
	if ca == nil {
		return true
	}
	chain, ok := chainFrom(ctx)
	return !ok || ca.IssuerOf(chain[0]) != nil
}
