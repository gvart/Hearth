// SPDX-License-Identifier: AGPL-3.0-only

package talos

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// pemPair returns a self-signed certificate and its key, PEM, base64 as a
// talosconfig holds them.
func pemPair(t *testing.T) (crt, key string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "talos"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString
	return enc(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		enc(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}))
}

func TestLoadConfig(t *testing.T) {
	crt, key := pemPair(t)
	file := `context: lab
contexts:
  lab:
    endpoints: [10.0.0.1, "10.0.0.9:50001"]
    nodes: [10.0.0.1, 10.0.0.2]
    ca: ` + crt + `
    crt: ` + crt + `
    key: ` + key + `
  bare:
    endpoints: [cp.lan]
    ca: ` + crt + `
    crt: ` + crt + `
    key: ` + key + `
  noendpoints:
    ca: ` + crt + `
  badca:
    endpoints: [10.0.0.1]
    ca: "!!"
    crt: ` + crt + `
    key: ` + key + `
`
	path := filepath.Join(t.TempDir(), "talosconfig")
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, context string
		nodes         []string
		wantEndpoints []string
		wantNodes     []string
		wantErr       string
	}{
		{"current context", "", nil, []string{"10.0.0.1:50000", "10.0.0.9:50001"}, []string{"10.0.0.1", "10.0.0.2"}, ""},
		{"nodes override", "", []string{"10.0.0.3", " "}, []string{"10.0.0.1:50000", "10.0.0.9:50001"}, []string{"10.0.0.3"}, ""},
		{"no nodes: the endpoints", "bare", nil, []string{"cp.lan:50000"}, []string{"cp.lan"}, ""},
		{"unknown context", "nope", nil, nil, nil, `no context "nope"`},
		{"no endpoints", "noendpoints", nil, nil, nil, "has no endpoints"},
		{"bad ca", "badca", nil, nil, nil, "ca is not base64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := LoadConfig(path, tt.context, tt.nodes)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v; want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(c.Endpoints, tt.wantEndpoints) || !slices.Equal(c.Nodes, tt.wantNodes) {
				t.Errorf("endpoints %v, nodes %v; want %v, %v", c.Endpoints, c.Nodes, tt.wantEndpoints, tt.wantNodes)
			}
			if c.TLS == nil || len(c.TLS.Certificates) != 1 || c.TLS.RootCAs == nil {
				t.Errorf("TLS = %+v; want a client certificate and the CA", c.TLS)
			}
		})
	}
}

func TestLoadConfigRefuses(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tests := []struct{ name, path, want string }{
		{"missing file", filepath.Join(dir, "nope"), "read talosconfig"},
		{"no current context", write("empty", "context: \"\"\ncontexts: {}\n"), "no current context"},
		{"not yaml", write("bad", "context: [\n"), "parse talosconfig"},
		{"too large", write("large", "# "+strings.Repeat("x", maxConfigSize)), "larger than 1 MiB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadConfig(tt.path, "", nil); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v; want %q", err, tt.want)
			}
		})
	}
}

// Read asks every node through the endpoint, decodes each node's reply and
// keeps a node apid cannot reach as an error, without failing the read.
func TestClientRead(t *testing.T) {
	f := newFakeAPI(t, "10.0.0.3")
	c := New(f.config([]string{f.endpoint()}, "10.0.0.2", "10.0.0.1", "10.0.0.3"))
	nodes, err := c.Read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 {
		t.Fatalf("nodes = %+v; want 3", nodes)
	}
	n := nodes[0]
	boot := time.Unix(1778351076, 0).UTC()
	if n.Address != "10.0.0.1" || n.Hostname != "talos-10-0-0-1" || n.Version != "v1.12.7" || n.Arch != "amd64" ||
		n.Platform != "metal" || n.MemTotal != 16144744*1024 || n.MemAvailable != 11955304*1024 ||
		n.Load1 != 1.5 || n.Load5 != 0.75 || n.Load15 != 0.25 || !n.BootTime.Equal(boot) || n.Error != "" {
		t.Errorf("node = %+v", n)
	}
	wantSvcs := []Service{
		{ID: "apid", State: "Running", Health: HealthHealthy},
		{ID: "dashboard", State: "Running", Health: HealthUnknown},
		{ID: "etcd", State: "Running", Health: HealthHealthy},
	}
	if !slices.Equal(n.Services, wantSvcs) || !n.Healthy {
		t.Errorf("services = %+v, healthy %v; want %+v, healthy", n.Services, n.Healthy, wantSvcs)
	}
	if n := nodes[1]; n.Healthy || n.Services[2].Health != HealthUnhealthy || n.Services[2].Message != "context deadline exceeded" {
		t.Errorf("node with a failing etcd = %+v; want unhealthy", n)
	}
	if n := nodes[2]; n.Address != "10.0.0.3" || !strings.Contains(n.Error, "no route to host") || n.Version != "" || n.Healthy {
		t.Errorf("unreachable node = %+v; want only its error", n)
	}

	calls, nodeMD := f.called()
	want := []string{methodVersion, methodHostname, methodServiceList, methodMemory, methodLoadAvg, methodSystemStat}
	if !slices.Equal(calls, want) {
		t.Errorf("calls = %v; want %v", calls, want)
	}
	for _, md := range nodeMD {
		if !slices.Equal(md, []string{"10.0.0.2", "10.0.0.1", "10.0.0.3"}) {
			t.Errorf("nodes metadata = %v", md)
		}
	}
}

// The client calls nothing outside its read allowlist, whatever it is asked.
func TestClientCallsOnlyReadMethods(t *testing.T) {
	f := newFakeAPI(t)
	c := New(f.config([]string{f.endpoint()}, "10.0.0.1"))
	for _, m := range []string{"Upgrade", "Reboot", "Shutdown", "Reset", "ApplyConfiguration", "ServiceRestart", "EtcdLeaveCluster", ""} {
		if _, err := c.call(t.Context(), m, []string{"10.0.0.1"}); !errors.Is(err, errNotRead) {
			t.Errorf("call(%q) err = %v; want errNotRead", m, err)
		}
	}
	if calls, _ := f.called(); len(calls) != 0 {
		t.Errorf("calls = %v; want none", calls)
	}
}

// An endpoint that does not answer is skipped for the next one; with none
// answering, Read fails.
func TestClientEndpointFallback(t *testing.T) {
	f := newFakeAPI(t)
	dead := "127.0.0.1:1"
	c := New(f.config([]string{dead, f.endpoint()}, "10.0.0.1"))
	nodes, err := c.Read(t.Context())
	if err != nil || len(nodes) != 1 || nodes[0].Version != "v1.12.7" {
		t.Fatalf("Read = %+v, %v; want the node through the second endpoint", nodes, err)
	}
	if got := c.Target(); got != "lab@"+dead {
		t.Errorf("Target = %q", got)
	}
	c = New(f.config([]string{dead}, "10.0.0.1"))
	if _, err := c.Read(t.Context()); err == nil || !strings.Contains(err.Error(), dead) {
		t.Errorf("err = %v; want the dead endpoint named", err)
	}
}

// A client that does not trust the server's certificate reads nothing.
func TestClientVerifiesTheAPI(t *testing.T) {
	f := newFakeAPI(t)
	cfg := f.config([]string{f.endpoint()}, "10.0.0.1")
	cfg.TLS.RootCAs = nil
	if _, err := New(cfg).Read(t.Context()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("err = %v; want a certificate error", err)
	}
	if calls, _ := f.called(); len(calls) != 0 {
		t.Errorf("calls = %v; want none", calls)
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	for _, b := range [][]byte{{0x0a, 0x05, 0x01}, {0xff}} {
		if _, err := replies(b, func(meta, field) error { return nil }); !errors.Is(err, errMalformed) {
			t.Errorf("replies(%x) err = %v; want errMalformed", b, err)
		}
	}
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// A read goes through policy as talos.read and is audited; a failed read
// keeps the last nodes and says why.
func TestReader(t *testing.T) {
	ctx := t.Context()
	st := newStore(t)
	f := newFakeAPI(t)
	cfg := f.config([]string{f.endpoint()}, "10.0.0.1")
	r := NewReader(ReaderConfig{Client: New(cfg), Policy: policy.New(st.Audit())})
	if s := r.Snapshot(); s.State != StateConnecting {
		t.Errorf("state before a read = %q", s.State)
	}
	if err := r.Read(ctx); err != nil {
		t.Fatal(err)
	}
	if s := r.Snapshot(); s.State != StateOK || len(s.Nodes) != 1 || s.ReadAt.IsZero() {
		t.Errorf("snapshot = %+v", s)
	}
	f.srv.Close()
	if err := r.Read(ctx); err == nil {
		t.Fatal("no error with the API gone")
	}
	if s := r.Snapshot(); s.State != StateUnavailable || s.Error == "" || len(s.Nodes) != 1 {
		t.Errorf("snapshot after a failed read = %+v; want the last nodes kept", s)
	}
	entries, err := st.Audit().List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("audit = %+v; want 2 entries", entries)
	}
	for _, e := range entries {
		if e.Action != string(policy.TalosRead) || e.ActorKind != policy.ActorHub || e.Target != "lab@"+f.endpoint() {
			t.Errorf("audit entry = %+v", e)
		}
	}
}

// A policy that denies the read class stops reads before the API is asked.
func TestReaderDenied(t *testing.T) {
	st := newStore(t)
	pc := policy.Config{Classes: map[policy.Class]policy.Mode{policy.Read: policy.ModeDeny}}
	if err := pc.Validate(); err != nil {
		t.Fatal(err)
	}
	f := newFakeAPI(t)
	r := NewReader(ReaderConfig{Client: New(f.config([]string{f.endpoint()}, "10.0.0.1")), Policy: policy.NewWithConfig(st.Audit(), nil, pc)})
	if err := r.Read(t.Context()); !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("err = %v; want ErrDenied", err)
	}
	if calls, _ := f.called(); len(calls) != 0 {
		t.Errorf("calls = %v; want none", calls)
	}
}
