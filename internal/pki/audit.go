// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"slices"
	"sync"
)

// Audit entry seals (#387). A master seals each audit entry it appends with
// an HMAC-SHA256 keyed by a key derived (HKDF-SHA256) from the hub CA key:
// only a hub holding that key, a master, can make or check a seal. Every CA
// generation has a key of its own, named by an id derived from the CA's
// certificate, so an entry names the key it was sealed with and a rotation
// leaves earlier entries verifiable: the masters keep the earlier keys
// (sealed, in the store) once the CA key they came from is gone.

// auditMACInfo binds the derived key to its one use.
const auditMACInfo = "hearth audit mac v1"

// AuditKey is the audit MAC key of one hub CA generation.
type AuditKey struct {
	// ID names the generation: AuditKeyID of its CA certificate.
	ID string
	// Key is the HMAC-SHA256 key. Never log or persist it in clear.
	Key []byte
}

// AuditKeyID is the id of the audit MAC key of the CA whose certificate is
// cert: the first 16 hex digits of its fingerprint.
func AuditKeyID(cert *x509.Certificate) string { return FingerprintHex(cert)[:16] }

// DeriveAuditKey derives the audit MAC key from a hub CA private key in
// PKCS #8 DER.
func DeriveAuditKey(caKeyDER []byte) ([]byte, error) {
	if len(caKeyDER) == 0 {
		return nil, fmt.Errorf("derive the audit key: %w", ErrNoCAKey)
	}
	key, err := hkdf.Key(sha256.New, caKeyDER, nil, auditMACInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("derive the audit key: %w", err)
	}
	return key, nil
}

// AuditKeys returns the audit MAC keys of the CA keys this hub holds, the
// serving CA's first (the one new entries are sealed with): none on a hub
// without the CA key.
func (c *CA) AuditKeys() ([]AuditKey, error) {
	s := c.state()
	pairs := []keyPair{s.serving()}
	if s.next != nil {
		if s.cutover {
			pairs = append(pairs, s.cur)
		} else {
			pairs = append(pairs, *s.next)
		}
	}
	var out []AuditKey
	for _, kp := range pairs {
		if kp.key == nil {
			continue
		}
		der, err := x509.MarshalPKCS8PrivateKey(kp.key)
		if err != nil {
			return nil, fmt.Errorf("encode CA key: %w", err)
		}
		key, err := DeriveAuditKey(der)
		if err != nil {
			return nil, err
		}
		out = append(out, AuditKey{ID: AuditKeyID(kp.cert), Key: key})
	}
	return out, nil
}

// AuditKeyring seals and checks audit entries: it seals with the serving
// CA's audit key and checks with any key it knows, those of the CA keys the
// hub holds and the earlier ones added with AddEarlier. It follows the CA:
// a key the hub no longer holds (a rotation finished) stays known.
type AuditKeyring struct {
	ca *CA
	mu sync.RWMutex
	// held are the keys of the CA keys held, the sealing one first.
	held []AuditKey
	// earlier are the other keys known, by id.
	earlier map[string][]byte
}

// NewAuditKeyring returns the keyring of ca, kept up to date as ca changes.
func NewAuditKeyring(ca *CA) (*AuditKeyring, error) {
	k := &AuditKeyring{ca: ca, earlier: map[string][]byte{}}
	if err := k.Refresh(); err != nil {
		return nil, err
	}
	ca.OnChange(func() { _ = k.Refresh() })
	return k, nil
}

// Refresh reads the CA's keys again. A key no longer held is kept as an
// earlier one.
func (k *AuditKeyring) Refresh() error {
	held, err := k.ca.AuditKeys()
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, old := range k.held {
		if !slices.ContainsFunc(held, func(h AuditKey) bool { return h.ID == old.ID }) {
			k.earlier[old.ID] = old.Key
		}
	}
	k.held = held
	return nil
}

// Held returns the keys of the CA keys the hub holds, the sealing one first.
func (k *AuditKeyring) Held() []AuditKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return slices.Clone(k.held)
}

// AddEarlier makes the keyring know keys, those of earlier CAs.
func (k *AuditKeyring) AddEarlier(keys ...AuditKey) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, key := range keys {
		k.earlier[key.ID] = slices.Clone(key.Key)
	}
}

// CanVerify reports whether the keyring holds a CA's key: whether this hub
// can seal and check entries at all.
func (k *AuditKeyring) CanVerify() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.held) > 0
}

// MAC seals msg with the serving CA's audit key and returns the key's id:
// ErrNoCAKey on a hub without the CA key.
func (k *AuditKeyring) MAC(msg []byte) (string, []byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if len(k.held) == 0 {
		return "", nil, ErrNoCAKey
	}
	return k.held[0].ID, auditMAC(k.held[0].Key, msg), nil
}

// Check reports whether mac seals msg under the key kid (ok), and whether
// the keyring knows that key at all (known).
func (k *AuditKeyring) Check(kid string, msg, mac []byte) (known, ok bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	key, found := k.earlier[kid]
	for _, h := range k.held {
		if h.ID == kid {
			key, found = h.Key, true
		}
	}
	if !found {
		return false, false
	}
	return true, hmac.Equal(auditMAC(key, msg), mac)
}

func auditMAC(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
