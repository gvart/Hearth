// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/gvart/hearth/internal/pki"
)

func hubCert(t *testing.T, ca *pki.CA, id string) tls.Certificate {
	t.Helper()
	cert, err := loadOrIssueNodeCert(t.TempDir(), ca, id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func deviceCert(t *testing.T, ca *pki.CA) tls.Certificate {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, "pi")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.SignClientCSR(csr, "pi", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
}

// TestTransportAuthenticatesHubs checks both directions of the raft mTLS: a
// listener only completes handshakes with hub certificates from its CA, and
// a dialer only trusts such listeners.
func TestTransportAuthenticatesHubs(t *testing.T) {
	ca, other := newTestCA(t), newTestCA(t)
	ln, err := listenTLS(t.Context(), "127.0.0.1:0", "", hubCert(t, ca, "server"), ca)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c) // echo; completes the handshake
			}()
		}
	}()

	dial := func(cfg *tls.Config) error {
		d := &tls.Dialer{Config: cfg}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		c, err := d.DialContext(ctx, "tcp", ln.Addr().String())
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		// TLS 1.3 reports a rejected client certificate on the first read.
		if _, err := c.Write([]byte("x")); err != nil {
			return err
		}
		_, err = c.Read(make([]byte, 1))
		return err
	}

	if err := dial(clientTLS(hubCert(t, ca, "peer"), ca)); err != nil {
		t.Fatalf("hub peer rejected: %v", err)
	}
	rejected := map[string]*tls.Config{
		"device certificate":         clientTLS(deviceCert(t, ca), ca),
		"hub certificate of another": clientTLS(hubCert(t, other, "peer"), ca),
		"no certificate":             {MinVersion: tls.VersionTLS13, InsecureSkipVerify: true},
	}
	for name, cfg := range rejected {
		if err := dial(cfg); err == nil {
			t.Errorf("%s: connection accepted", name)
		}
	}
	// A dialer refuses a listener whose certificate is a device's.
	devLn, err := listenTLS(t.Context(), "127.0.0.1:0", "", deviceCert(t, ca), ca)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = devLn.Close() })
	go func() {
		c, err := devLn.Accept()
		if err == nil {
			_, _ = io.Copy(io.Discard, c)
			_ = c.Close()
		}
	}()
	if _, err := ln.Dial(raft.ServerAddress(devLn.Addr().String()), 5*time.Second); err == nil {
		t.Error("dialer trusted a listener with a device certificate")
	}
}
