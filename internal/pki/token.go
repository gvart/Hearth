// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// tokenPrefix versions the token string format.
const tokenPrefix = "hearth1"

const secretLen = 32

var b64 = base64.RawURLEncoding

// Token is an enrollment token: a single-use secret plus the fingerprint of the
// hub CA, so the agent can pin the hub before sending the secret.
//
// Token deliberately formats as "[REDACTED]" with fmt and slog; use Encode to get
// the string to hand to an operator.
type Token struct {
	// Secret is the random part. Only its hash is stored by the hub.
	Secret        string
	CAFingerprint [sha256.Size]byte
}

// NewToken returns a token with a fresh 32-byte secret pinned to ca.
func NewToken(ca *x509.Certificate) (Token, error) {
	var b [secretLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Token{}, fmt.Errorf("generate token secret: %w", err)
	}
	return Token{Secret: b64.EncodeToString(b[:]), CAFingerprint: Fingerprint(ca)}, nil
}

// Encode returns the token string: hearth1.<secret>.<ca-fingerprint>, both base64url.
func (t Token) Encode() string {
	return tokenPrefix + "." + t.Secret + "." + b64.EncodeToString(t.CAFingerprint[:])
}

// String redacts the token so it never leaks through %v or error wrapping.
func (t Token) String() string { return "[REDACTED]" }

// LogValue redacts the token in structured logs.
func (t Token) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// ParseToken parses a token string. Errors never echo the input.
func ParseToken(s string) (Token, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 3 || parts[0] != tokenPrefix {
		return Token{}, errors.New("parse token: want hearth1.<secret>.<fingerprint>")
	}
	secret, err := b64.DecodeString(parts[1])
	if err != nil || len(secret) != secretLen {
		return Token{}, errors.New("parse token: malformed secret")
	}
	fp, err := b64.DecodeString(parts[2])
	if err != nil || len(fp) != sha256.Size {
		return Token{}, errors.New("parse token: malformed CA fingerprint")
	}
	t := Token{Secret: parts[1]}
	copy(t.CAFingerprint[:], fp)
	return t, nil
}
