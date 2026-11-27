// SPDX-License-Identifier: AGPL-3.0-only

package unifi

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// ErrBadConnection is returned for a connection that cannot be used. Its
// messages never include the password or the API key.
var ErrBadConnection = errors.New("invalid unifi connection")

// Controller kinds, as the API names them.
const (
	// KindUniFiOS is a UniFi OS console (UDM, UCG, Cloud Key Gen2+, or the
	// UniFi OS Server): the Network application sits under /proxy/network.
	KindUniFiOS = "unifi_os"
	// KindClassic is a self-hosted UniFi Network application (the classic
	// controller, port 8443 by default).
	KindClassic = "classic"
)

// Auth modes, as the API names them.
const (
	AuthAPIKey   = "api_key"
	AuthPassword = "password"
)

// TLS modes, as the API names them. A controller is always https.
const (
	TLSSystem      = "system"
	TLSFingerprint = "fingerprint"
)

// DefaultSite is the short name of the site every controller starts with.
const DefaultSite = "default"

// Connection is how the hub reaches one controller: what is sealed in the store.
type Connection struct {
	// URL is the controller's https://host[:port].
	URL  string `json:"url"`
	Kind string `json:"kind"`
	// Site is the site's short name, as in /api/s/<site>/; "default" unless
	// the controller has several.
	Site string `json:"site"`
	// APIKey, on a UniFi OS console, replaces the login.
	APIKey   string `json:"api_key,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// Fingerprint pins the controller's certificate, which is self-signed on
	// most: its SHA-256, lowercase hex. Without one, the system roots verify it.
	Fingerprint string `json:"fingerprint,omitempty"`
}

var siteName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (c Connection) authMode() string {
	if c.APIKey != "" {
		return AuthAPIKey
	}
	return AuthPassword
}

func (c Connection) tlsMode() string {
	if c.Fingerprint != "" {
		return TLSFingerprint
	}
	return TLSSystem
}

func badConnection(msg string) error { return fmt.Errorf("%w: %s", ErrBadConnection, msg) }

func printable(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f })
}

// normalize checks c and returns it in its stored form.
func (c Connection) normalize() (Connection, error) {
	var err error
	if c.URL, err = normalizeURL(c.URL); err != nil {
		return Connection{}, err
	}
	if c.Kind != KindUniFiOS && c.Kind != KindClassic {
		return Connection{}, badConnection("the controller kind must be unifi_os or classic")
	}
	if c.Site = strings.TrimSpace(c.Site); c.Site == "" {
		c.Site = DefaultSite
	}
	if !siteName.MatchString(c.Site) {
		return Connection{}, badConnection("the site must be its short name, such as default")
	}
	c.APIKey = strings.TrimSpace(c.APIKey)
	c.Username = strings.TrimSpace(c.Username)
	if c.APIKey != "" {
		switch {
		case c.Kind != KindUniFiOS:
			return Connection{}, badConnection("an API key is for a UniFi OS console; a self-hosted controller takes a username and password")
		case c.Username != "" || c.Password != "":
			return Connection{}, badConnection("give an API key or a username and password, not both")
		case len(c.APIKey) > 255 || !printable(c.APIKey):
			return Connection{}, badConnection("the API key must be 1 to 255 characters, without spaces")
		}
	} else {
		if c.Username == "" || len(c.Username) > 64 || !printable(c.Username) {
			return Connection{}, badConnection("the username must be 1 to 64 characters, without spaces")
		}
		if c.Password == "" || len(c.Password) > 255 {
			return Connection{}, badConnection("the password must be 1 to 255 characters")
		}
	}
	if c.Fingerprint = strings.TrimSpace(c.Fingerprint); c.Fingerprint != "" {
		if c.Fingerprint, err = normalizeFingerprint(c.Fingerprint); err != nil {
			return Connection{}, err
		}
	}
	return c, nil
}

// normalizeURL returns the controller's address as https://host:port.
func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", badConnection("the URL cannot be parsed")
	}
	if u.Scheme != "https" || u.Hostname() == "" {
		return "", badConnection("the URL must be https://host[:port]: UniFi serves its API over https only")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", badConnection("the URL must be only https://host[:port]")
	}
	// A pasted address of the controller's web UI is the same controller.
	switch strings.Trim(u.Path, "/") {
	case "", "manage", "network":
	default:
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

// tlsConfig verifies the controller as c says. Verification is never off: a
// pinned fingerprint replaces the chain check with a stricter one.
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
			return errors.New("the controller sent no certificate")
		}
		got := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if !bytes.Equal(got[:], want) {
			return errors.New("the controller's certificate does not match the pinned fingerprint")
		}
		return nil
	}
	return cfg, nil
}
