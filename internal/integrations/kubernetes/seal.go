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
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer derives the kubeconfig sealing key from secret, the hub CA's
// private key in PKCS #8 DER.
func NewSealer(secret []byte) (*Sealer, error) { return NewPurposeSealer(secret, sealInfo) }

// NewPurposeSealer is NewSealer for another kind of secret: info names the
// purpose, so each purpose seals with a key of its own.
func NewPurposeSealer(secret []byte, info string) (*Sealer, error) {
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
	return &Sealer{aead: aead}, nil
}

// Seal encrypts plaintext for the cluster with ID id, which is bound as
// additional data: a sealed kubeconfig moved to another row fails to open.
func (s *Sealer) Seal(id string, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return s.aead.Seal(nonce, nonce, plaintext, []byte(id)), nil
}

// Open decrypts what Seal returned for the same id.
func (s *Sealer) Open(id string, sealed []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n+s.aead.Overhead() {
		return nil, errors.New("open sealed secret: too short")
	}
	out, err := s.aead.Open(nil, sealed[:n], sealed[n:], []byte(id))
	if err != nil {
		return nil, fmt.Errorf("open sealed secret: %w", err)
	}
	return out, nil
}
