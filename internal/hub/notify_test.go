// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/policy"
)

func TestNotifyAPI(t *testing.T) {
	published := make(chan map[string]string, 1)
	ntfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		if body["topic"] == "denied-s3cret" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":"forbidden"}`)
			return
		}
		published <- body
	}))
	defer ntfy.Close()
	n, err := notify.Parse([]byte("channels:\n" +
		"  phone: {type: ntfy, url: \"" + ntfy.URL + "\", topic: lab-s3cret, token: tk_s3cret}\n" +
		"  broken: {type: ntfy, url: \"" + ntfy.URL + "\", topic: denied-s3cret}\n"))
	if err != nil {
		t.Fatal(err)
	}
	f := newAPIFixture(t, true, func(c *Config) { c.Notify = n })
	if err := f.st.Admin().CreateSession(t.Context(), "s", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	cookie := testCookie("s")

	if r := f.do(t, http.MethodGet, "/api/v1/notify/channels", "", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list = %d", r.StatusCode)
	}
	if r := f.do(t, http.MethodPost, "/api/v1/notify/channels/phone/test", "", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated test = %d", r.StatusCode)
	}
	r := f.do(t, http.MethodGet, "/api/v1/notify/channels", "", cookie)
	if r.StatusCode != http.StatusOK || string(r.body) != `{"channels":[{"name":"broken","type":"ntfy"},{"name":"phone","type":"ntfy"}]}`+"\n" {
		t.Fatalf("list = %d %s", r.StatusCode, r.body)
	}

	if r := f.do(t, http.MethodPost, "/api/v1/notify/channels/phone/test", "", cookie); r.StatusCode != http.StatusNoContent {
		t.Fatalf("test send = %d %s", r.StatusCode, r.body)
	}
	if got := <-published; got["topic"] != "lab-s3cret" || got["title"] != "Hearth" || !strings.HasPrefix(got["message"], "Test notification") {
		t.Errorf("published %v", got)
	}

	r = f.do(t, http.MethodPost, "/api/v1/notify/channels/broken/test", "", cookie)
	if r.StatusCode != http.StatusBadGateway || !strings.Contains(string(r.body), "answered 403 Forbidden: forbidden") {
		t.Errorf("failed send = %d %s", r.StatusCode, r.body)
	}
	if r := f.do(t, http.MethodPost, "/api/v1/notify/channels/pager/test", "", cookie); r.StatusCode != http.StatusNotFound {
		t.Errorf("unknown channel = %d %s", r.StatusCode, r.body)
	}

	entries, err := f.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var tests []string
	for _, e := range entries {
		if e.Action != string(policy.NotifyTest) {
			continue
		}
		tests = append(tests, e.Target+" "+e.Decision+" "+e.Result)
		if e.ActorKind != policy.ActorWeb || strings.Contains(e.Result+string(e.Detail), "s3cret") {
			t.Errorf("audit entry = %+v", e)
		}
	}
	if len(tests) != 2 {
		t.Errorf("notify.test audit entries = %q, want phone ok and broken error", tests)
	}
	if strings.Contains(string(r.body), "s3cret") || strings.Contains(f.logs.String(), "s3cret") {
		t.Error("a secret leaked into an answer or the log")
	}
}

func TestNotifyAPIDisabled(t *testing.T) {
	f := newAPIFixture(t, true)
	if err := f.st.Admin().CreateSession(t.Context(), "s", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r := f.do(t, http.MethodGet, "/api/v1/notify/channels", "", testCookie("s")); r.StatusCode != http.StatusNotFound {
		t.Errorf("list without a notifier = %d", r.StatusCode)
	}
}
