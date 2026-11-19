// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
// It reports whether either changed.
func (r *runner) saveRenewal(w *agentv1.Welcome) (bool, error) {
	dir := r.cfg.DataDir
	changed := false
	if bundle := w.GetCaBundle(); len(bundle) > 0 {
		cur, err := os.ReadFile(filepath.Join(dir, CAFile))
		if err != nil {
			return false, err
		}
		if !bytes.Equal(cur, bundle) {
			if !x509.NewCertPool().AppendCertsFromPEM(bundle) {
				return false, errors.New("the hub sent no CA certificate")
			}
			if err := replaceFile(dir, CAFile, bundle); err != nil {
				return false, err
			}
			changed = true
		}
	}
	if cert := w.GetCertificate(); len(cert) > 0 {
		key, err := os.ReadFile(filepath.Join(dir, KeyFile))
		if err != nil {
			return changed, err
		}
		if _, err := tls.X509KeyPair(cert, key); err != nil {
			return changed, err
		}
		if err := replaceFile(dir, CertFile, cert); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}
