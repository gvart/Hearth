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

// Token string prefixes. They version the format and keep the two kinds apart:
// an enrollment token cannot be passed off as a join token or vice versa.
const (
	tokenPrefix     = "hearth1"
	joinTokenPrefix = "hearthj1"
	// hubTokenPrefix is an enrollment token that also names the hub that
	// owns it: an AP cluster master (docs/design/ap-cluster.md §6).
	hubTokenPrefix = "hearth2"
)

// maxHubURLLen bounds the hub URL a token carries.
const maxHubURLLen = 512

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
	// HubURL is the agent-facing URL of the hub that owns the token, when
	// the token names one (EncodeHub): an agent enrolls there.
	HubURL string
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
func (t Token) Encode() string { return t.encode(tokenPrefix) }

// EncodeJoin returns the token as a cluster join token:
// hearthj1.<secret>.<ca-fingerprint>. A joining hub pins the CA by the
// fingerprint before it sends the secret.
func (t Token) EncodeJoin() string { return t.encode(joinTokenPrefix) }

// EncodeHub returns the token string naming hubURL, the agent-facing URL of
// the AP cluster master that owns it: hearth2.<secret>.<ca-fingerprint>.<url>,
// all base64url. Only a master of an AP cluster issues these; a single hub
// and a Raft cluster keep issuing Encode's.
func (t Token) EncodeHub(hubURL string) string {
	return t.encode(hubTokenPrefix) + "." + b64.EncodeToString([]byte(hubURL))
}

func (t Token) encode(prefix string) string {
	return prefix + "." + t.Secret + "." + b64.EncodeToString(t.CAFingerprint[:])
}

// String redacts the token so it never leaks through %v or error wrapping.
func (t Token) String() string { return "[REDACTED]" }

// LogValue redacts the token in structured logs.
func (t Token) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// ParseToken parses an enrollment token string, of either form (Encode,
// EncodeHub). Errors never echo the input.
func ParseToken(s string) (Token, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, hubTokenPrefix+".") {
		return parseToken(s, tokenPrefix)
	}
	i := strings.LastIndexByte(s, '.')
	u, err := b64.DecodeString(s[i+1:])
	if err != nil || len(u) == 0 || len(u) > maxHubURLLen {
		return Token{}, errors.New("parse token: malformed hub URL")
	}
	t, err := parseToken(s[:i], hubTokenPrefix)
	if err != nil {
		return Token{}, err
	}
	t.HubURL = string(u)
	return t, nil
}

// ParseJoinToken parses a cluster join token string. Errors never echo the input.
func ParseJoinToken(s string) (Token, error) { return parseToken(s, joinTokenPrefix) }

func parseToken(s, prefix string) (Token, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 3 || parts[0] != prefix {
		return Token{}, errors.New("parse token: want " + prefix + ".<secret>.<fingerprint>")
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
