// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/pki"
)

const caContentType = "application/x-x509-ca-cert"

// RegisterCARoute adds GET /ca.crt to mux: the hub CA certificate, and only the
// certificate, for browsers and phones to trust once so the UI works over
// HTTPS. It is PEM by default and DER with ?format=der, which some Windows and
// iOS tools prefer. It belongs on the plain-HTTP listener: a device that does
// not trust the CA yet cannot fetch it over HTTPS without a warning.
func RegisterCARoute(mux *http.ServeMux, ca *x509.Certificate) {
	RegisterCARouteFunc(mux, func() *x509.Certificate { return ca })
}

// RegisterCARouteFunc is RegisterCARoute serving the certificate ca returns
// at each request: the CA the hub serves, which a hub CA rotation changes.
func RegisterCARouteFunc(mux *http.ServeMux, ca func() *x509.Certificate) {
	mux.HandleFunc("GET /ca.crt", func(w http.ResponseWriter, r *http.Request) {
		cert := ca()
		pemBytes, derBytes := pki.EncodeCertPEM(cert), cert.Raw
		body := pemBytes
		switch r.URL.Query().Get("format") {
		case "", "pem":
		case "der":
			body = derBytes
		default:
			http.Error(w, "format must be pem or der", http.StatusBadRequest)
			return
		}
		// No Content-Disposition: iOS Safari offers a profile install only
		// for a certificate served inline.
		w.Header().Set("Content-Type", caContentType)
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, "ca.crt", time.Time{}, bytes.NewReader(body))
	})
}

// TLSInfoJSON is the body of GET /tls: what the UI needs to point a browser on
// plain HTTP at the HTTPS address. None of it is secret; anyone can read the
// same from the hub's certificate.
type TLSInfoJSON struct {
	// Port is the HTTPS (agent) port.
	Port string `json:"port"`
	// Hosts are the names the hub certificate is valid for.
	Hosts []string `json:"hosts"`
	// CAFingerprint is the SHA-256 of the CA certificate, as colon-separated
	// upper-case hex pairs (openssl's format).
	CAFingerprint string `json:"ca_fingerprint"`
	// LANOrigin, when set, replaces the browser's origin in links and
	// snippets for other devices, as the browser's host resolves only here
	// (hearth.local, localhost): see lanOrigin.
	LANOrigin string `json:"lan_origin,omitempty"`
}

// tlsInfo is unauthenticated: the banner that uses it shows on the login page.
func (a *api) tlsInfo(w http.ResponseWriter, r *http.Request) {
	hosts := a.certHosts()
	if hosts == nil {
		hosts = []string{}
	}
	writeJSON(w, http.StatusOK, TLSInfoJSON{
		Port: a.agentPort, Hosts: hosts, CAFingerprint: formatFingerprint(a.ca.Cert()),
		LANOrigin: a.lanOrigin(r.Host, r.TLS != nil),
	})
}

func formatFingerprint(cert *x509.Certificate) string {
	fp := pki.Fingerprint(cert)
	parts := make([]string, len(fp))
	for i, b := range fp {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
