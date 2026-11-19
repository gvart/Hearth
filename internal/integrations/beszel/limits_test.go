// SPDX-License-Identifier: AGPL-3.0-only

package beszel_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gvart/hearth/internal/integrations/beszel"
	"github.com/gvart/hearth/internal/integrations/beszel/beszelmock"
)

// page is a listing page of n empty items that claims totalPages pages.
func page(n, totalPages int) string {
	return `{"page":1,"perPage":200,"totalItems":-1,"totalPages":` + strconv.Itoa(totalPages) +
		`,"items":[` + strings.TrimSuffix(strings.Repeat(`{},`, n), ",") + `]}`
}

// A page is cut at the page size the hub asked for, whatever the server
// sends.
func TestSystemsPageCappedAtPerPage(t *testing.T) {
	m := beszelmock.New(beszelmock.Email, beszelmock.Password)
	m.SetBody(page(5000, 1))
	got, err := newClient(t, m, beszelmock.Password, nil).Systems(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 200 {
		t.Errorf("systems = %d; want the 200 asked for", len(got))
	}
}

// A server that never stops paging is cut off with an error once the total
// passes the cap, instead of growing the hub without bound.
func TestSystemsTotalCapped(t *testing.T) {
	m := beszelmock.New(beszelmock.Email, beszelmock.Password)
	m.SetBody(page(200, 1_000_000))
	got, err := newClient(t, m, beszelmock.Password, nil).Systems(t.Context())
	if err == nil || !strings.Contains(err.Error(), "more than 5000 systems") {
		t.Fatalf("err = %v (%d systems); want the cap", err, len(got))
	}
	if got != nil {
		t.Errorf("systems = %d; want none with the error", len(got))
	}
}

// A redirect is not followed: it would carry the email and password to
// another host.
func TestNoRedirect(t *testing.T) {
	var leaked atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), beszelmock.Password) || r.Header.Get("Authorization") != "" {
			leaked.Add(1)
		}
		leaked.Add(1)
	}))
	t.Cleanup(other.Close)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", other.URL+"/api/collections/users/auth-with-password")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirect.Close)
	c, err := beszel.New(redirect.URL, beszelmock.Email, beszelmock.Password, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Systems(t.Context()); err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Errorf("err = %v; want the redirect refused", err)
	}
	if n := leaked.Load(); n != 0 {
		t.Errorf("the redirect target got %d requests; want none", n)
	}
}
