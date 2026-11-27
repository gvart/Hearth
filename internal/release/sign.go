// SPDX-License-Identifier: AGPL-3.0-only

package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
)

// Each release's checksums.txt is signed with the project's Ed25519 release
// key (#359): checksums.txt.sig holds the base64 of the signature over the
// exact bytes of checksums.txt. An agent upgrading itself checks it against
// the public key compiled in before it trusts any hash in checksums.txt, so
// whoever can only change a release's assets cannot make agents install
// their code.

// PublicKey is the base64 of the raw 32-byte Ed25519 public key that signs
// releases.
const PublicKey = "abVwO44ZL8113oIxlfmwu4cCx28LGqrHkkBJNLg0wvs="

// SignatureSuffix is appended to checksums.txt to name its signature asset.
const SignatureSuffix = ".sig"

// TrustedKey is the public key releases are checked against: PublicKey,
// except in a build with the e2etestkey tag (the end-to-end tests' image
// only, whose releases are signed with a test key; see key_e2e.go). There
// is no variable a plain -ldflags -X could set, and nothing at run time,
// neither a flag nor the environment, changes it.
func TrustedKey() (ed25519.PublicKey, error) {
	return ParsePublicKey(trustedKey())
}

// ParsePublicKey decodes the base64 of a raw Ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("the release public key is not the base64 of a 32-byte Ed25519 key")
	}
	return ed25519.PublicKey(b), nil
}

// ParseSeed decodes the base64 of a 32-byte Ed25519 seed into its private
// key. The error never quotes s.
func ParseSeed(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, errors.New("the signing key is not the base64 of a 32-byte Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(b), nil
}

// Sign is the content of checksums.txt.sig for checksums: the base64 of
// key's signature over it, and a newline.
func Sign(key ed25519.PrivateKey, checksums []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, checksums)) + "\n")
}

// Verify checks sig, the content of checksums.txt.sig, against checksums
// and key.
func Verify(key ed25519.PublicKey, checksums, sig []byte) error {
	s, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(s) != ed25519.SignatureSize {
		return errors.New("the signature of checksums.txt is malformed")
	}
	if !ed25519.Verify(key, checksums, s) {
		return errors.New("the signature of checksums.txt does not verify with the Hearth release key")
	}
	return nil
}
