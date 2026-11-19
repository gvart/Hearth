// SPDX-License-Identifier: AGPL-3.0-only

package netalertx_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/integrations/netalertx"
	"github.com/gvart/hearth/internal/integrations/netalertx/netalertxmock"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// A device list longer than the cap is refused with an error, instead of
// growing the hub without bound.
func TestRecordsCapped(t *testing.T) {
	m := netalertxmock.New(netalertxmock.Token)
	m.SetBody(`{"success":true,"devices":[` + strings.TrimSuffix(strings.Repeat(`{},`, 4097), ",") + `]}`)
	c, err := netalertx.New(serve(t, m), netalertxmock.Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := c.Records(t.Context())
	if err == nil || !strings.Contains(err.Error(), "more than 4096 devices") {
		t.Fatalf("err = %v (%d records); want the cap", err, len(recs))
	}
}

// Exactly the cap is fine.
func TestRecordsAtCap(t *testing.T) {
	m := netalertxmock.New(netalertxmock.Token)
	dev := `{"devMac":"2c:cf:67:00:00:01","devLastIP":"192.168.1.2"},`
	m.SetBody(`{"success":true,"devices":[` + strings.TrimSuffix(strings.Repeat(dev, 4096), ",") + `]}`)
	c, err := netalertx.New(serve(t, m), netalertxmock.Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := c.Records(t.Context())
	if err != nil || len(recs) != 4096 {
		t.Fatalf("Records = %d, %v; want 4096", len(recs), err)
	}
}

// The most devices the client accepts all pass the importer's own limit on
// hosts per source, so the two limits agree.
func TestImportAtCap(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	var b strings.Builder
	b.WriteString(`{"success":true,"devices":[`)
	for i := range 4096 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"devMac":"02:00:00:00:%02x:%02x","devLastIP":"10.%d.%d.1"}`, i/256, i%256, i/256, i%256)
	}
	b.WriteString(`]}`)
	m := netalertxmock.New(netalertxmock.Token)
	m.SetBody(b.String())
	c, err := netalertx.New(serve(t, m), netalertxmock.Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	im := discovery.NewImporter(discovery.ImportConfig{
		Sources: []discovery.Source{c}, Hosts: st.NetworkHosts(), Policy: policy.New(st.Audit()),
	})
	if err := im.Import(ctx); err != nil {
		t.Fatalf("import of the most devices the client accepts: %v", err)
	}
	hosts, err := st.NetworkHosts().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 4096 {
		t.Errorf("hosts = %d; want 4096", len(hosts))
	}
}

// A redirect is not followed: it would carry the token to another host.
func TestNoRedirect(t *testing.T) {
	var reached atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	t.Cleanup(other.Close)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", other.URL+"/devices")
		w.WriteHeader(http.StatusPermanentRedirect)
	}))
	t.Cleanup(redirect.Close)
	c, err := netalertx.New(redirect.URL, netalertxmock.Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Records(t.Context()); err == nil || !strings.Contains(err.Error(), "HTTP 308") {
		t.Errorf("err = %v; want the redirect refused", err)
	}
	if n := reached.Load(); n != 0 {
		t.Errorf("the redirect target got %d requests; want none", n)
	}
}

// A huge error message from the server is clipped before it reaches the
// error, the log and the audit entry.
func TestErrorMessageClipped(t *testing.T) {
	huge := strings.Repeat("x", 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"message":"` + huge + `"}`))
	}))
	t.Cleanup(srv.Close)
	c, err := netalertx.New(srv.URL, netalertxmock.Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Records(t.Context())
	if err == nil || len(err.Error()) > 512 || !strings.Contains(err.Error(), "HTTP 500: xxx") {
		t.Errorf("err has %d bytes; want the message clipped", len(err.Error()))
	}
}
