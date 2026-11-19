// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync/atomic"
)

// sealInfo binds the derived key to its one use. A new purpose, or a new
// scheme for this one, takes a new info string and so a different key.
const sealInfo = "hearth kubeconfig seal v1"

// Sealer encrypts kubeconfigs at rest with AES-256-GCM.
//
// Its key is derived (HKDF-SHA256) from the hub CA's private key, so it
// exists exactly where that key does: in every hub voter's data dir (0600),
// replicated only over the pinned join channel. Nothing new needs storing
// or replicating, and the database, the Raft log and snapshots only ever
// hold ciphertext.
//
// While the hub CA is rotated a hub holds two CA keys: the Sealer is then a
// keyring (see SetSecrets) that seals with the newest key and opens with any.
type Sealer struct {
	info string
	// keys are the AEADs derived from the secrets, the one that seals first.
	keys atomic.Pointer[[]cipher.AEAD]
}

// NewSealer derives the kubeconfig sealing key from secret, the hub CA's
// private key in PKCS #8 DER.
func NewSealer(secret []byte) (*Sealer, error) { return NewPurposeSealer(secret, sealInfo) }

// NewPurposeSealer is NewSealer for another kind of secret: info names the
// purpose, so each purpose seals with a key of its own.
func NewPurposeSealer(secret []byte, info string) (*Sealer, error) {
	s := &Sealer{info: info}
	if err := s.SetSecrets(secret); err != nil {
		return nil, err
	}
	return s, nil
}

// SetSecrets replaces the sealer's keys with those derived from secrets, hub
// CA private keys in PKCS #8 DER: Seal uses the first, Open tries each. It is
// safe to call while the sealer is in use.
func (s *Sealer) SetSecrets(secrets ...[]byte) error {
	if len(secrets) == 0 {
		return errors.New("new sealer: no secret")
	}
	keys := make([]cipher.AEAD, 0, len(secrets))
	for _, secret := range secrets {
		aead, err := deriveAEAD(secret, s.info)
		if err != nil {
			return err
		}
		keys = append(keys, aead)
	}
	s.keys.Store(&keys)
	return nil
}

func deriveAEAD(secret []byte, info string) (cipher.AEAD, error) {
	if len(secret) == 0 {
		return nil, errors.New("new sealer: empty secret")
	}
	key, err := hkdf.Key(sha256.New, secret, nil, info, 32)
	if err != nil {
		return nil, fmt.Errorf("new sealer: derive key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new sealer: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new sealer: %w", err)
	}
	return aead, nil
}

// Seal encrypts plaintext for the cluster with ID id, which is bound as
// additional data: a sealed kubeconfig moved to another row fails to open.
func (s *Sealer) Seal(id string, plaintext []byte) ([]byte, error) {
	aead := (*s.keys.Load())[0]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, []byte(id)), nil
}

// Open decrypts what Seal returned for the same id, with any of the keys.
func (s *Sealer) Open(id string, sealed []byte) ([]byte, error) {
	out, _, err := s.open(id, sealed)
	return out, err
}

// open is Open that also reports whether the key Seal uses opened it.
func (s *Sealer) open(id string, sealed []byte) ([]byte, bool, error) {
	keys := *s.keys.Load()
	// Every key is AES-256-GCM: one nonce size and overhead.
	n := keys[0].NonceSize()
	if len(sealed) < n+keys[0].Overhead() {
		return nil, false, errors.New("open sealed secret: too short")
	}
	var last error
	for i, aead := range keys {
		out, err := aead.Open(nil, sealed[:n], sealed[n:], []byte(id))
		if err == nil {
			return out, i == 0, nil
		}
		last = err
	}
	return nil, false, fmt.Errorf("open sealed secret: %w", last)
}

// Reseal returns sealed encrypted again with the key Seal uses, and whether
// it had to: when that key opens sealed already, it returns sealed unchanged
// and false.
func (s *Sealer) Reseal(id string, sealed []byte) ([]byte, bool, error) {
	out, current, err := s.open(id, sealed)
	if err != nil || current {
		return sealed, false, err
	}
	resealed, err := s.Seal(id, out)
	if err != nil {
		return sealed, false, err
	}
	return resealed, true, nil
}
