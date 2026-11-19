// SPDX-License-Identifier: AGPL-3.0-only

package proxmox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/proxmox/pvemock"
)

// fingerprintOf is the pin of srv's certificate.
func fingerprintOf(srv *httptest.Server) string {
	sum := sha256.Sum256(srv.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

func caOf(srv *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
}

func TestTLSVerification(t *testing.T) {
	mock := pvemock.New(pvemock.Token)
	srv := httptest.NewTLSServer(mock)
	t.Cleanup(srv.Close)
	wrongPin := strings.Repeat("ab", sha256.Size)
	for _, tc := range []struct {
		name string
		conn Connection
		ok   bool
	}{
		{"pinned fingerprint", Connection{Fingerprint: fingerprintOf(srv)}, true},
		{"wrong fingerprint", Connection{Fingerprint: wrongPin}, false},
		{"configured CA", Connection{CAPEM: caOf(srv)}, true},
		{"another CA", Connection{CAPEM: genCA(t)}, false},
		{"neither: the system roots do not know it", Connection{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.conn.URL, tc.conn.Token = srv.URL, pvemock.Token
			c, err := newClient(tc.conn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.close)
			before := len(mock.Requests())
			_, err = c.resources(t.Context())
			if tc.ok && err != nil {
				t.Fatalf("resources: %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatal("resources succeeded against an untrusted certificate")
				}
				if n := len(mock.Requests()); n != before {
					t.Errorf("the token reached an unverified server: %d requests", n-before)
				}
			}
		})
	}
}

func TestNormalizeConnection(t *testing.T) {
	const secretPart = "7f8d2a54-very-secret" //nolint:gosec // a test value
	valid := Connection{URL: "https://pve.lan:8006", Token: "hearth@pve!hub=" + secretPart}
	mod := func(f func(*Connection)) Connection {
		c := valid
		f(&c)
		return c
	}
	for _, tc := range []struct {
		name string
		conn Connection
	}{
		{"plain http", mod(func(c *Connection) { c.URL = "http://pve.lan:8006" })},
		{"no host", mod(func(c *Connection) { c.URL = "https://" })},
		{"credentials in the URL", mod(func(c *Connection) { c.URL = "https://root:pw@pve.lan" })},
		{"a path", mod(func(c *Connection) { c.URL = "https://pve.lan/api2/json" })},
		{"a password instead of a token", mod(func(c *Connection) { c.Token = "root@pam" })},
		{"no token id", mod(func(c *Connection) { c.Token = "hearth@pve=" + secretPart })},
		{"no realm", mod(func(c *Connection) { c.Token = "hearth!hub=" + secretPart })},
		{"no secret", mod(func(c *Connection) { c.Token = "hearth@pve!hub=" })},
		{"a newline in the token", mod(func(c *Connection) { c.Token = "hearth@pve!hub=a\nX-Evil: " + secretPart })},
		{"a CA and a fingerprint", mod(func(c *Connection) { c.CAPEM, c.Fingerprint = genCA(t), strings.Repeat("ab", 32) })},
		{"a CA that is no certificate", mod(func(c *Connection) { c.CAPEM = "not pem" })},
		{"a short fingerprint", mod(func(c *Connection) { c.Fingerprint = "AB:CD" })},
		{"a fingerprint that is no hex", mod(func(c *Connection) { c.Fingerprint = strings.Repeat("zz", 32) })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.conn.normalize()
			if !errors.Is(err, ErrBadConnection) {
				t.Fatalf("normalize = %v, want ErrBadConnection", err)
			}
			if strings.Contains(err.Error(), secretPart) {
				t.Errorf("the error quotes the token: %v", err)
			}
		})
	}

	got, err := Connection{
		URL: " https://pve.lan/ ", Token: "PVEAPIToken=hearth@pve!hub=" + secretPart,
		Fingerprint: strings.Repeat("AB:", 31) + "AB",
	}.normalize()
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://pve.lan:8006" || got.Token != "hearth@pve!hub="+secretPart ||
		got.Fingerprint != strings.Repeat("ab", 32) {
		t.Errorf("normalize = %+v", got)
	}
}

// clientFor is a client trusting srv.
func clientFor(t *testing.T, srv *httptest.Server) *client {
	t.Helper()
	c, err := newClient(Connection{URL: srv.URL, Token: pvemock.Token, Fingerprint: fingerprintOf(srv)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.close)
	return c
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var followed bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	t.Cleanup(target.Close)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	if _, err := clientFor(t, srv).resources(t.Context()); err == nil {
		t.Error("a redirect counted as an answer")
	}
	if followed {
		t.Error("the client followed a redirect")
	}
}

func TestRequestRespectsCancellation(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	c := clientFor(t, srv)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.resources(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("resources = %v, want the context's deadline", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("cancellation took %v", d)
	}
}

func TestClientHasTimeouts(t *testing.T) {
	c, err := newClient(Connection{URL: "https://pve.lan:8006", Token: pvemock.Token})
	if err != nil {
		t.Fatal(err)
	}
	if c.hc.Timeout != requestTimeout || c.hc.Timeout <= 0 {
		t.Errorf("request timeout = %v", c.hc.Timeout)
	}
}

func TestErrorsNeverCarryTheToken(t *testing.T) {
	_, secret, _ := strings.Cut(pvemock.Token, "=")
	for _, message := range []string{"bad token " + pvemock.Token, "bad secret " + secret} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": message})
		}))
		_, err := clientFor(t, srv).resources(t.Context())
		srv.Close()
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Errorf("error = %v", err)
		}
	}
}

func TestLenientNumbers(t *testing.T) {
	for in, want := range map[string]num{
		`1`: 1, `0`: 0, `"1"`: 1, `""`: 0, `true`: 1, `false`: 0, `null`: 0, `0.25`: 0.25, `"105"`: 105, `"odd"`: 0,
		`"NaN"`: 0, `"nan"`: 0, `"Inf"`: 0, `"-Inf"`: 0, `"Infinity"`: 0, `"+Infinity"`: 0, `"1e999"`: 0,
	} {
		var n num
		if err := json.Unmarshal([]byte(in), &n); err != nil || n != want {
			t.Errorf("%s = %v, %v; want %v", in, n, err, want)
		}
	}
}
