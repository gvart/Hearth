// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

// A key proof shows that a hub holds the private key of a CA, without
// sending it: a signature by that key over a message naming what it is for.
// During a hub CA rotation of an AP cluster a master proves it holds the
// current CA key to be handed the next one: what a member says of its roles
// on the gossip is its own word, holding the key is not.

// ErrBadKeyProof is a key proof that does not verify.
var ErrBadKeyProof = errors.New("the CA key proof does not verify")

// ProveKey signs msg with the key of the CA whose certificate's fingerprint
// is caFP, the current or the next one. It fails with ErrNoCAKey if this hub
// does not hold that key.
func (c *CA) ProveKey(caFP string, msg []byte) ([]byte, error) {
	s := c.state()
	pairs := []keyPair{s.cur}
	if s.next != nil {
		pairs = append(pairs, *s.next)
	}
	for _, kp := range pairs {
		if FingerprintHex(kp.cert) != caFP {
			continue
		}
		if kp.key == nil {
			return nil, ErrNoCAKey
		}
		return signProof(kp.key, msg)
	}
	return nil, ErrNoCAKey
}

// CanProve reports whether ProveKey(caFP, ...) would sign: this CA holds
// the key of the CA certificate whose fingerprint is caFP.
func (c *CA) CanProve(caFP string) bool {
	s := c.state()
	pairs := []keyPair{s.cur}
	if s.next != nil {
		pairs = append(pairs, *s.next)
	}
	for _, kp := range pairs {
		if FingerprintHex(kp.cert) == caFP {
			return kp.key != nil
		}
	}
	return false
}

func signProof(key crypto.Signer, msg []byte) ([]byte, error) {
	switch key.Public().(type) {
	case ed25519.PublicKey:
		return key.Sign(rand.Reader, msg, crypto.Hash(0))
	case *ecdsa.PublicKey, *rsa.PublicKey:
		d := sha256.Sum256(msg)
		return key.Sign(rand.Reader, d[:], crypto.SHA256)
	}
	return nil, fmt.Errorf("prove a CA key: unsupported key type %T", key.Public())
}

// VerifyKeyProof checks that sig is a key proof of msg by the key of ca.
func VerifyKeyProof(ca *x509.Certificate, msg, sig []byte) error {
	var algo x509.SignatureAlgorithm
	switch ca.PublicKey.(type) {
	case ed25519.PublicKey:
		algo = x509.PureEd25519
	case *ecdsa.PublicKey:
		algo = x509.ECDSAWithSHA256
	case *rsa.PublicKey:
		algo = x509.SHA256WithRSA
	default:
		return ErrBadKeyProof
	}
	if len(sig) == 0 || ca.CheckSignature(algo, msg, sig) != nil {
		return ErrBadKeyProof
	}
	return nil
}
