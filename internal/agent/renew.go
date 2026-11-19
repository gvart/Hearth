// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// errRenewed ends a session whose Welcome renewed the agent's certificate or
// changed the CAs it trusts during a hub CA rotation: the agent reconnects
// with them.
var errRenewed = errors.New("identity renewed")

func newTransport(id *identity) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		DialContext:         dialer.DialContext,
		TLSClientConfig:     id.tls,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
		// The hub sends nothing between messages; pings detect a dead peer.
		HTTP2: &http.HTTP2Config{SendPingTimeout: 30 * time.Second, PingTimeout: 15 * time.Second},
	}
}

// saveRenewal saves what a Welcome carries for a hub CA rotation: the CAs to
// trust first, then the agent's certificate of the new CA, each replaced
// atomically, so a crash in between leaves an identity that still connects.
// Both are checked first (see checkRenewal), against the CA that verified the
// hub of this session. It reports whether either changed.
func (r *runner) saveRenewal(w *agentv1.Welcome) (bool, error) {
	dir := r.cfg.DataDir
	bundle, cert := w.GetCaBundle(), w.GetCertificate()
	if len(bundle) == 0 && len(cert) == 0 {
		return false, nil
	}
	cur, err := os.ReadFile(filepath.Join(dir, CAFile))
	if err != nil {
		return false, err
	}
	key, err := os.ReadFile(filepath.Join(dir, KeyFile))
	if err != nil {
		return false, err
	}
	if bytes.Equal(cur, bundle) {
		bundle = nil
	}
	held, err := os.ReadFile(filepath.Join(dir, CertFile))
	if err != nil {
		return false, err
	}
	if err := checkRenewal(cur, bundle, cert, key, held, r.id.verifiedRoot.Load()); err != nil {
		return false, err
	}
	changed := false
	if len(bundle) > 0 {
		if err := replaceFile(dir, CAFile, bundle); err != nil {
			return false, err
		}
		changed = true
	}
	if len(cert) > 0 {
		if err := replaceFile(dir, CertFile, cert); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// maxTrusted is the most CAs an agent trusts: the old and the new one of a
// hub CA rotation.
const maxTrusted = 2

// checkRenewal decides whether an agent trusting the CAs of cur takes the
// CAs of bundle (nil: no change) and the certificate cert (nil: none), all
// PEM, from a hub its TLS handshake verified against the CA root. A bundle
// that adds a CA is taken only with a renewal: at most two CAs, root among
// them, and a certificate for key that one of them issued. Any other bundle
// must only drop CAs of cur. Any new bundle must keep the CA of held, the
// certificate the agent holds now, so a hub cannot make it drop that CA.
// A certificate must be for key and of a CA trusted after the change.
// Whatever fails refuses both.
func checkRenewal(cur, bundle, cert, key, held []byte, root *x509.Certificate) error {
	curCAs, err := parseCerts(cur)
	if err != nil {
		return fmt.Errorf("the trusted CAs: %w", err)
	}
	trusted := curCAs
	if len(bundle) > 0 {
		if trusted, err = parseCerts(bundle); err != nil {
			return fmt.Errorf("the hub's CAs: %w", err)
		}
		shrink := true
		for _, c := range trusted {
			shrink = shrink && containsCert(curCAs, c)
		}
		switch {
		case shrink:
		case len(cert) == 0:
			return errors.New("the hub sent a CA to trust without a certificate of it")
		case len(trusted) > maxTrusted:
			return fmt.Errorf("the hub sent %d CAs to trust, more than %d", len(trusted), maxTrusted)
		case root == nil || !containsCert(trusted, root):
			return errors.New("the hub's CAs leave out the CA that verified it")
		}
	}
	if len(bundle) > 0 {
		// The CA of the certificate the agent holds now stays trusted: the
		// hub chooses any certificate it hands out, not this one.
		b, _ := pem.Decode(held)
		if b == nil {
			return errors.New("the agent certificate: no PEM certificate")
		}
		now, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return fmt.Errorf("the agent certificate: %w", err)
		}
		if !issuedByOne(now, trusted) {
			return errors.New("the hub's CAs leave out the CA of the agent's certificate")
		}
	}
	if len(cert) == 0 {
		return nil
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return fmt.Errorf("the renewed certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("the renewed certificate: %w", err)
	}
	if !issuedByOne(leaf, trusted) {
		return errors.New("the renewed certificate is not of a CA to trust")
	}
	return nil
}

func issuedByOne(c *x509.Certificate, cas []*x509.Certificate) bool {
	for _, ca := range cas {
		if c.CheckSignatureFrom(ca) == nil {
			return true
		}
	}
	return false
}

// parseCerts parses every certificate of PEM data, which must hold one or
// more CA certificates and nothing else.
func parseCerts(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			if len(bytes.TrimSpace(rest)) > 0 || len(out) == 0 {
				return nil, errors.New("not a list of PEM CA certificates")
			}
			return out, nil
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil || b.Type != "CERTIFICATE" || !c.IsCA {
			return nil, errors.New("not a list of PEM CA certificates")
		}
		out = append(out, c)
	}
}

func containsCert(certs []*x509.Certificate, c *x509.Certificate) bool {
	for _, x := range certs {
		if x.Equal(c) {
			return true
		}
	}
	return false
}
