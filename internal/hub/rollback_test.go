// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
	"github.com/gvart/hearth/internal/store"
)

// TestRollbackReported checks that a rollback an agent tells of in its Hello
// is audited once per Hello, kept in the device's facts through its later
// Facts and reconnects while it reports the same version, and dropped once
// it reports another.
func TestRollbackReported(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	reg := NewRegistry(RegistryConfig{Store: st, Log: slog.New(slog.DiscardHandler)})
	as := NewAgentStream(slog.New(slog.DiscardHandler), time.Second, reg)
	as.audit = st.Audit()
	path, h := agentv1connect.NewAgentServiceHandler(as)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(withDeviceID(r.Context(), "dev-1")))
	}))
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	tr := &http.Transport{Protocols: new(http.Protocols)}
	tr.Protocols.SetUnencryptedHTTP2(true)
	t.Cleanup(tr.CloseIdleConnections)
	client := agentv1connect.NewAgentServiceClient(&http.Client{Transport: tr}, srv.URL)

	// session connects with a Hello of version and rolledBackFrom, sends
	// one Facts message of the same, and hangs up.
	session := func(version, rolledBackFrom string) {
		t.Helper()
		stream := client.Connect(t.Context())
		msg := hello(ProtocolMajor)
		msg.GetHello().AgentVersion, msg.GetHello().RolledBackFrom = version, rolledBackFrom
		if err := stream.Send(msg); err != nil {
			t.Fatal(err)
		}
		if m, err := stream.Receive(); err != nil || m.GetWelcome() == nil {
			t.Fatalf("want Welcome, got %v, %v", m, err)
		}
		facts := hello(ProtocolMajor).GetHello()
		facts.AgentVersion = version
		if err := stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Facts{Facts: facts}}); err != nil {
			t.Fatal(err)
		}
		_ = stream.CloseRequest()
		_, _ = stream.Receive() // the hub ends the stream once it read all
		_ = stream.CloseResponse()
	}
	rolledBackFrom := func() string {
		t.Helper()
		d, err := st.Devices().Get(t.Context(), "dev-1")
		if err != nil {
			t.Fatal(err)
		}
		var f Facts
		if err := json.Unmarshal(d.Facts, &f); err != nil {
			t.Fatal(err)
		}
		return f.RolledBackFrom
	}
	audited := func() []store.AuditEntry {
		t.Helper()
		all, err := st.Audit().List(t.Context(), 100)
		if err != nil {
			t.Fatal(err)
		}
		var out []store.AuditEntry
		for _, e := range all {
			if e.Action == ActionUpgradeRolledBack {
				out = append(out, e)
			}
		}
		return out
	}

	// Anything but a release tag of at most 64 bytes is dropped, unaudited.
	for _, bad := range []string{"not a version", "v1.2.0\nforged log line", "v1.2.0-" + strings.Repeat("a", 64)} {
		session("v1.0.0", bad)
		if got := rolledBackFrom(); got != "" {
			t.Fatalf("rolled_back_from %q kept as %q, want it dropped", bad, got)
		}
	}
	if n := len(audited()); n != 0 {
		t.Fatalf("%d rollback audit entries for invalid reports, want none", n)
	}

	session("v1.0.0", "v1.2.0")
	if got := rolledBackFrom(); got != "v1.2.0" {
		t.Fatalf("rolled_back_from after the Hello and a Facts = %q, want v1.2.0", got)
	}
	entries := audited()
	if len(entries) != 1 || entries[0].ActorID != "dev-1" || entries[0].Target != "dev-1" || entries[0].Decision != policy.Allow ||
		strings.Contains(entries[0].Result, "v1.2.0") || !strings.Contains(string(entries[0].Detail), `"rolled_back_from":"v1.2.0"`) {
		t.Fatalf("audit = %+v, want one rollback entry for dev-1, the version in its detail only", entries)
	}

	// The same report again (a lost Welcome) audits nothing more.
	session("v1.0.0", "v1.2.0")
	if n := len(audited()); n != 1 {
		t.Errorf("%d rollback audit entries after the same report again, want 1", n)
	}

	// A reconnect that no longer says it keeps it, and audits nothing more.
	session("v1.0.0", "")
	if got := rolledBackFrom(); got != "v1.2.0" {
		t.Errorf("rolled_back_from after a reconnect on the same version = %q, want v1.2.0 kept", got)
	}
	if n := len(audited()); n != 1 {
		t.Errorf("%d rollback audit entries, want 1", n)
	}

	// Upgraded since: the notice is gone.
	session("v1.2.1", "")
	if got := rolledBackFrom(); got != "" {
		t.Errorf("rolled_back_from after an upgrade = %q, want none", got)
	}
}

func TestAgentVersionRolledBack(t *testing.T) {
	t.Parallel()
	a := &api{version: "v1.2.0"}
	facts, err := json.Marshal(Facts{AgentVersion: "v1.0.0", RolledBackFrom: "v1.2.0", ProtocolMinor: 13, ReleaseTarget: "linux_amd64"})
	if err != nil {
		t.Fatal(err)
	}
	v := a.deviceJSON(store.Device{ID: "dev-1", Facts: facts}).AgentVersion
	if v == nil || v.RolledBackFrom != "v1.2.0" {
		t.Fatalf("agent version = %+v, want rolled back from v1.2.0", v)
	}
}
