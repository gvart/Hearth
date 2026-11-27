// SPDX-License-Identifier: AGPL-3.0-only

package opnsense

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrBadConnection is returned for a connection that cannot be used. Its
// messages never include the key or the secret.
var ErrBadConnection = errors.New("invalid opnsense connection")

// Connection is how the hub reaches one firewall: what is sealed in the store.
type Connection struct {
	// URL is the firewall's web GUI, https://host[:port]; the hub calls
	// /api on it.
	URL string `json:"url"`
	// Key and Secret are an API key of an OPNsense user, sent as HTTP basic
	// auth. Both are secrets.
	Key    string `json:"key"`
	Secret string `json:"secret"`
	// Fingerprint pins the firewall's certificate: its SHA-256, lowercase
	// hex. Without one, the system roots verify it.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// TLS modes, as the API names them. There is no plain http: the key and
// secret go with every request.
const (
	TLSSystem      = "system"
	TLSFingerprint = "fingerprint"
)

// tlsMode names how c verifies the firewall.
func (c Connection) tlsMode() string {
	if c.Fingerprint != "" {
		return TLSFingerprint
	}
	return TLSSystem
}

func badConnection(msg string) error { return fmt.Errorf("%w: %s", ErrBadConnection, msg) }

// validCredential reports whether s can go in a basic auth header as
// OPNsense reads it: it splits key:secret on every colon.
func validCredential(s string) bool {
	return s != "" && len(s) <= 255 && !strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f || r == ':' })
}

// normalize checks c and returns it in its stored form.
func (c Connection) normalize() (Connection, error) {
	var err error
	if c.URL, err = normalizeURL(c.URL); err != nil {
		return Connection{}, err
	}
	c.Key, c.Secret = strings.TrimSpace(c.Key), strings.TrimSpace(c.Secret)
	if !validCredential(c.Key) {
		return Connection{}, badConnection("the API key must be 1 to 255 characters, without spaces or colons")
	}
	if !validCredential(c.Secret) {
		return Connection{}, badConnection("the API secret must be 1 to 255 characters, without spaces or colons")
	}
	c.Fingerprint = strings.TrimSpace(c.Fingerprint)
	if c.Fingerprint != "" {
		if c.Fingerprint, err = normalizeFingerprint(c.Fingerprint); err != nil {
			return Connection{}, err
		}
	}
	return c, nil
}

// normalizeURL returns the firewall's address as https://host:port.
func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", badConnection("the URL cannot be parsed")
	}
	if u.Scheme == "http" {
		return "", badConnection("the URL must be https://: the API key would cross the network in the clear")
	}
	if u.Scheme != "https" || u.Hostname() == "" {
		return "", badConnection("the URL must be https://host[:port]")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", badConnection("the URL must be only https://host[:port]")
	}
	// A pasted web GUI or API address is the same firewall.
	path := strings.Trim(u.Path, "/")
	if path != "" && path != "api" && path != "ui" {
		return "", badConnection("the URL must be only https://host[:port]")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return "https://" + net.JoinHostPort(u.Hostname(), port), nil
}

// normalizeFingerprint returns a SHA-256 fingerprint as lowercase hex, from
// the AA:BB:... form openssl prints.
func normalizeFingerprint(raw string) (string, error) {
	fp := strings.ToLower(strings.ReplaceAll(raw, ":", ""))
	if b, err := hex.DecodeString(fp); err != nil || len(b) != sha256.Size {
		return "", badConnection("the fingerprint must be a SHA-256 fingerprint, as AA:BB:...")
	}
	return fp, nil
}

// tlsConfig verifies the firewall as c says. Verification is never off: a
// pinned fingerprint, the explicit option for a self-signed certificate,
// replaces the chain check with a stricter one.
func tlsConfig(c Connection) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.tlsMode() != TLSFingerprint {
		return cfg, nil
	}
	want, err := hex.DecodeString(c.Fingerprint)
	if err != nil {
		return nil, badConnection("the fingerprint is not hex")
	}
	// VerifyConnection below takes over from the chain check, on every
	// connection including resumed ones.
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("the firewall sent no certificate")
		}
		got := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if !bytes.Equal(got[:], want) {
			return errors.New("the firewall's certificate does not match the pinned fingerprint")
		}
		return nil
	}
	return cfg, nil
}
