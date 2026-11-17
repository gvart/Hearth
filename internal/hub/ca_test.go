// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
)

func TestCARoute(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.LoadOrCreateCA(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, pki.CAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	mux := http.NewServeMux()
	RegisterCARoute(mux, ca.Cert())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	get := func(t *testing.T, path string) (int, http.Header, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, resp.Header, b
	}

	tests := []struct {
		name, path string
		parse      func([]byte) (*x509.Certificate, error)
	}{
		{"pem", "/ca.crt", pki.ParseCertPEM},
		{"explicit pem", "/ca.crt?format=pem", pki.ParseCertPEM},
		{"der", "/ca.crt?format=der", x509.ParseCertificate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, header, body := get(t, tt.path)
			if status != http.StatusOK {
				t.Fatalf("status = %d", status)
			}
			if ct := header.Get("Content-Type"); ct != "application/x-x509-ca-cert" {
				t.Errorf("Content-Type = %q", ct)
			}
			cert, err := tt.parse(body)
			if err != nil {
				t.Fatalf("parse body: %v", err)
			}
			if !cert.Equal(ca.Cert()) || !cert.IsCA {
				t.Error("served certificate is not the hub CA")
			}
			// Only the certificate: no key material, and nothing after it.
			if bytes.Contains(body, []byte("PRIVATE KEY")) || bytes.Contains(body, keyBlock.Bytes) {
				t.Fatal("served the CA private key")
			}
			if tt.name != "der" {
				if block, rest := pem.Decode(body); block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
					t.Errorf("body is not exactly one CERTIFICATE block")
				}
			} else if !bytes.Equal(body, ca.Cert().Raw) {
				t.Error("DER body is not exactly the CA certificate")
			}
		})
	}

	if status, _, _ := get(t, "/ca.crt?format=p12"); status != http.StatusBadRequest {
		t.Errorf("unknown format: status %d, want 400", status)
	}
}
