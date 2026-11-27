// SPDX-License-Identifier: AGPL-3.0-only

package openwrt

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
// messages never include the password.
var ErrBadConnection = errors.New("invalid openwrt connection")

// Connection is how the hub reaches one router: what is sealed in the store.
type Connection struct {
	// URL is the router's web server, http(s)://host[:port]; the hub calls
	// /ubus on it.
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	// Fingerprint pins an https router's certificate: its SHA-256,
	// lowercase hex. Without one, the system roots verify it.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// TLS modes, as the API names them.
const (
	// TLSNone is plain http: the password crosses the LAN in the clear.
	TLSNone        = "none"
	TLSSystem      = "system"
	TLSFingerprint = "fingerprint"
)

// tlsMode names how c verifies the router.
func (c Connection) tlsMode() string {
	switch {
	case strings.HasPrefix(c.URL, "http://"):
		return TLSNone
	case c.Fingerprint != "":
		return TLSFingerprint
	}
	return TLSSystem
}

func badConnection(msg string) error { return fmt.Errorf("%w: %s", ErrBadConnection, msg) }

// normalize checks c and returns it in its stored form.
func (c Connection) normalize() (Connection, error) {
	var err error
	if c.URL, err = normalizeURL(c.URL); err != nil {
		return Connection{}, err
	}
	c.Username = strings.TrimSpace(c.Username)
	if c.Username == "" || len(c.Username) > 64 || strings.ContainsFunc(c.Username, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return Connection{}, badConnection("the username must be 1 to 64 characters, without spaces")
	}
	if c.Password == "" || len(c.Password) > 255 {
		return Connection{}, badConnection("the password must be 1 to 255 characters")
	}
	c.Fingerprint = strings.TrimSpace(c.Fingerprint)
	if c.Fingerprint != "" {
		if strings.HasPrefix(c.URL, "http://") {
			return Connection{}, badConnection("a fingerprint is for an https:// URL")
		}
		if c.Fingerprint, err = normalizeFingerprint(c.Fingerprint); err != nil {
			return Connection{}, err
		}
	}
	return c, nil
}

// normalizeURL returns the router's address as http(s)://host:port.
func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", badConnection("the URL cannot be parsed")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", badConnection("the URL must be http(s)://host[:port]")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", badConnection("the URL must be only http(s)://host[:port]")
	}
	// A pasted LuCI or ubus address is the same router.
	path := strings.Trim(u.Path, "/")
	if path != "" && path != "ubus" && path != "cgi-bin/luci" {
		return "", badConnection("the URL must be only http(s)://host[:port]")
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(u.Hostname(), port), nil
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

// tlsConfig verifies an https router as c says. Verification is never off: a
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
			return errors.New("the router sent no certificate")
		}
		got := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if !bytes.Equal(got[:], want) {
			return errors.New("the router's certificate does not match the pinned fingerprint")
		}
		return nil
	}
	return cfg, nil
}
