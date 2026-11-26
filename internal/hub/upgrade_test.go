// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
)

const testArchiveSum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// upgradeFixture is a hub of version v1.2.0 whose releases a test server
// serves, with device dev-1 enrolled.
type upgradeFixture struct {
	*apiFixture
	client  agentv1connect.AgentServiceClient
	release *httptest.Server
}

func newUpgradeFixture(t *testing.T, version string, pcfg policy.Config) *upgradeFixture {
	t.Helper()
	release := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.2.0/checksums.txt" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("f", 64) + "  hearth_1.2.0_linux_arm64.tar.gz\n" +
			testArchiveSum + "  hearth_1.2.0_linux_amd64.tar.gz\n"))
	}))
	t.Cleanup(release.Close)
	f := &upgradeFixture{release: release}
	f.apiFixture = newAPIFixture(t, true, withPolicy(pcfg), func(c *Config) {
		f.client, c.Agents = newExecClient(t, c.Store)
		c.Version, c.ReleaseBaseURL = version, release.URL
	})
	f.api.argon = testArgon
	enrollDevice(t, f.st, "dev-1")
	return f
}

// connectUpgrader connects dev-1 as an agent of protocol minor and the
// Hello set changes, and answers each UpgradeRequest with answer's result.
func (f *upgradeFixture) connectUpgrader(t *testing.T, minor uint32, set func(*agentv1.Hello),
	answer func(*agentv1.UpgradeRequest) *agentv1.UpgradeResult,
) <-chan *agentv1.UpgradeRequest {
	t.Helper()
	stream := f.client.Connect(t.Context())
	t.Cleanup(func() { _ = stream.CloseRequest(); _ = stream.CloseResponse() })
	h := hello(ProtocolMajor)
	h.GetHello().ProtocolVersion.Minor = minor
	h.GetHello().AgentVersion = "v1.0.0"
	if set != nil {
		set(h.GetHello())
	}
	if err := stream.Send(h); err != nil {
		t.Fatal(err)
	}
	if msg, err := stream.Receive(); err != nil || msg.GetWelcome() == nil {
		t.Fatalf("receive welcome: %v %v", msg, err)
	}
	reqs := make(chan *agentv1.UpgradeRequest, 4)
	go answerUpgrades(stream, reqs, answer)
	// The stream is attached once the device's facts say so.
	deadline := time.Now().Add(5 * time.Second)
	for !f.api.agents.Local("dev-1") {
		if time.Now().After(deadline) {
			t.Fatal("the agent never attached")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return reqs
}

func answerUpgrades(stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage],
	reqs chan<- *agentv1.UpgradeRequest, answer func(*agentv1.UpgradeRequest) *agentv1.UpgradeResult,
) {
	for {
		msg, err := stream.Receive()
		if err != nil {
			return
		}
		req := msg.GetUpgradeRequest()
		if req == nil {
			continue
		}
		reqs <- req
		res := answer(req)
		res.Id = req.GetId()
		_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_UpgradeResult{UpgradeResult: res}})
	}
}

func upgraded(req *agentv1.UpgradeRequest) *agentv1.UpgradeResult {
	return &agentv1.UpgradeResult{Ok: true, Version: req.GetVersion()}
}

func linuxAmd64(h *agentv1.Hello) { h.ReleaseTarget = "linux_amd64" }

func TestUpgradeDevice(t *testing.T) {
	t.Parallel()
	f := newUpgradeFixture(t, "v1.2.0", policy.Config{})
	reqs := f.connectUpgrader(t, minUpgradeMinor, linuxAmd64, upgraded)
	c := sessionCookie(t, f.login(t, testPassword))

	dev := decode[DeviceJSON](t, f.do(t, http.MethodGet, "/api/v1/devices/dev-1", "", c))
	if v := dev.AgentVersion; v == nil || v.Agent != "v1.0.0" || v.Hub != "v1.2.0" || !v.UpgradeAvailable || !v.RemoteUpgrade ||
		v.InstallCommand != "" {
		t.Fatalf("agent version = %+v, want an upgrade available, remotely", dev.AgentVersion)
	}

	resp := f.do(t, http.MethodPost, "/api/v1/devices/dev-1/upgrade", "", c)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upgrade = %d %s", resp.StatusCode, resp.body)
	}
	if got := decode[UpgradeJSON](t, resp); got.Version != "v1.2.0" || got.From != "v1.0.0" {
		t.Errorf("answer = %+v", got)
	}
	req := <-reqs
	if req.GetVersion() != "v1.2.0" || req.GetSha256() != testArchiveSum ||
		req.GetUrl() != f.release.URL+"/v1.2.0/hearth_1.2.0_linux_amd64.tar.gz" {
		t.Errorf("agent got %v", req)
	}
	entries := auditOf(t, f.apiFixture, policy.DeviceUpgrade)
	if len(entries) != 1 || entries[0].Decision != policy.Allow || entries[0].Target != "dev-1" || entries[0].Result != "ok" ||
		!strings.Contains(string(entries[0].Detail), `"version":"v1.2.0"`) {
		t.Errorf("audit = %+v", entries)
	}

	// An explicit version the release server does not have: audited too.
	resp = f.do(t, http.MethodPost, "/api/v1/devices/dev-1/upgrade", `{"version":"v1.3.0"}`, c)
	if resp.StatusCode != http.StatusBadGateway || errorCode(t, resp) != "release_unreachable" {
		t.Errorf("upgrade to a missing release = %d %s, want 502 release_unreachable", resp.StatusCode, resp.body)
	}
	if entries := auditOf(t, f.apiFixture, policy.DeviceUpgrade); len(entries) != 2 || entries[0].Result == "ok" {
		t.Errorf("audit after a missing release = %+v", entries)
	}
}

// TestUpgradeDeviceRefused checks every refusal: each is audited, and none
// reaches the agent.
func TestUpgradeDeviceRefused(t *testing.T) {
	t.Parallel()
	deny := policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeDeny}}
	tests := []struct {
		name     string
		version  string
		pcfg     policy.Config
		minor    uint32
		set      func(*agentv1.Hello)
		noReauth bool
		body     string
		status   int
		code     string
		audit    string // the decision audited, "" for none
	}{
		{name: "re-auth missing", minor: minUpgradeMinor, set: linuxAmd64, noReauth: true,
			status: http.StatusForbidden, code: "reauth_required", audit: policy.Deny},
		{name: "policy deny", pcfg: deny, minor: minUpgradeMinor, set: linuxAmd64,
			status: http.StatusForbidden, code: "forbidden", audit: policy.Deny},
		{name: "old agent", minor: minUpgradeMinor - 2, set: linuxAmd64,
			status: http.StatusConflict, code: "agent_too_old", audit: policy.Deny},
		{name: "kubernetes agent", minor: minUpgradeMinor,
			set:    func(h *agentv1.Hello) { h.NoSelfUpgrade = "this agent runs in a Kubernetes pod: upgrade its image instead" },
			status: http.StatusConflict, code: "cannot_upgrade", audit: policy.Deny},
		{name: "dev hub without a version", version: "dev", minor: minUpgradeMinor, set: linuxAmd64,
			status: http.StatusConflict, code: "no_version"},
		{name: "not a release", minor: minUpgradeMinor, set: linuxAmd64, body: `{"version":"latest"}`,
			status: http.StatusBadRequest, code: "bad_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newUpgradeFixture(t, cmpOr(tt.version, "v1.2.0"), tt.pcfg)
			reqs := f.connectUpgrader(t, tt.minor, tt.set, upgraded)
			c := sessionCookie(t, f.login(t, testPassword))
			if tt.noReauth {
				f.api.reauths.forgetAll()
			}
			resp := f.do(t, http.MethodPost, "/api/v1/devices/dev-1/upgrade", tt.body, c)
			if resp.StatusCode != tt.status || errorCode(t, resp) != tt.code {
				t.Fatalf("upgrade = %d %s, want %d %s", resp.StatusCode, resp.body, tt.status, tt.code)
			}
			if tt.status == http.StatusConflict && strings.Contains(string(resp.body), "denied by policy") {
				t.Errorf("refusal %s says more than its reason", resp.body)
			}
			select {
			case req := <-reqs:
				t.Fatalf("the agent got %v", req)
			default:
			}
			entries := auditOf(t, f.apiFixture, policy.DeviceUpgrade)
			if tt.audit == "" {
				if len(entries) != 0 {
					t.Errorf("audit = %+v, want none", entries)
				}
				return
			}
			if len(entries) != 1 || entries[0].Decision != tt.audit {
				t.Errorf("audit = %+v, want one %s", entries, tt.audit)
			}
		})
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// An agent too old to upgrade itself is shown the installer's command.
func TestDeviceAgentVersionOldAgent(t *testing.T) {
	t.Parallel()
	f := newUpgradeFixture(t, "v1.2.0", policy.Config{})
	f.connectUpgrader(t, minUpgradeMinor-2, nil, upgraded)
	c := sessionCookie(t, f.login(t, testPassword))
	dev := decode[DeviceJSON](t, f.do(t, http.MethodGet, "/api/v1/devices/dev-1", "", c))
	v := dev.AgentVersion
	if v == nil || v.RemoteUpgrade || !v.UpgradeAvailable || !strings.Contains(v.InstallCommand, "install.sh") ||
		!strings.HasSuffix(v.InstallCommand, "--version v1.2.0") {
		t.Fatalf("agent version of an old agent = %+v", v)
	}
	// The list leaves the command out.
	list := decode[struct {
		Devices []DeviceJSON `json:"devices"`
	}](t, f.do(t, http.MethodGet, "/api/v1/devices", "", c))
	if len(list.Devices) != 1 || list.Devices[0].AgentVersion == nil || list.Devices[0].AgentVersion.InstallCommand != "" {
		t.Errorf("listed = %+v", list.Devices)
	}
}

// The agent's own failure (a checksum mismatch) is audited as the result.
func TestUpgradeDeviceAgentFails(t *testing.T) {
	t.Parallel()
	f := newUpgradeFixture(t, "v1.2.0", policy.Config{})
	f.connectUpgrader(t, minUpgradeMinor, linuxAmd64, func(*agentv1.UpgradeRequest) *agentv1.UpgradeResult {
		return &agentv1.UpgradeResult{Error: "checksum mismatch: nothing was changed"}
	})
	c := sessionCookie(t, f.login(t, testPassword))
	resp := f.do(t, http.MethodPost, "/api/v1/devices/dev-1/upgrade", "", c)
	if resp.StatusCode != http.StatusBadGateway || errorCode(t, resp) != "upgrade_failed" || !strings.Contains(string(resp.body), "checksum mismatch") {
		t.Fatalf("upgrade = %d %s, want 502 upgrade_failed", resp.StatusCode, resp.body)
	}
	entries := auditOf(t, f.apiFixture, policy.DeviceUpgrade)
	if len(entries) != 1 || entries[0].Decision != policy.Allow || !strings.Contains(entries[0].Result, "checksum mismatch") {
		t.Errorf("audit = %+v", entries)
	}
}

func TestCompareRelease(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		a, b string
		want int
	}{
		{"v0.0.1", "v0.0.1", 0},
		{"v0.0.1", "v0.0.2", -1},
		{"v0.1.0", "v0.0.9", 1},
		{"v0.10.0", "v0.9.0", 1},
		{"v0.0.1-rc.9", "v0.0.1-rc.10", -1},
		{"v0.0.1-rc.10", "v0.0.1", -1},
		{"v0.0.1", "v0.0.1-rc.10", 1},
		{"v0.0.1-rc.1", "v0.0.1-rc.1.1", -1},
		{"v0.0.1-alpha", "v0.0.1-beta", -1},
		{"v0.0.1-1", "v0.0.1-alpha", -1},
	} {
		if got := compareRelease(tt.a, tt.b); got != tt.want {
			t.Errorf("compareRelease(%s, %s) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// An upgrade asked of master b runs on master a's stream, and a refusal
// there keeps its kind.
func TestForwardedUpgrade(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for _, tt := range []struct {
		minor   uint32
		wantErr error
	}{{minUpgradeMinor, nil}, {minUpgradeMinor - 2, policy.ErrBeyondCeiling}} {
		st := newTestStore(t)
		enrollDevice(t, st, "dev-1")
		client, onA := newExecClient(t, st)
		f := &upgradeFixture{client: client, apiFixture: &apiFixture{api: &api{agents: onA}}}
		f.connectUpgrader(t, tt.minor, linuxAmd64, upgraded)
		srv := httptest.NewServer(AgentsHandler(onA, nil, slog.New(slog.DiscardHandler)))
		t.Cleanup(srv.Close)
		u, _ := url.Parse(srv.URL)
		routes := st.DeviceRoutes()
		if err := routes.Set(ctx, "dev-1", "a", time.Now()); err != nil {
			t.Fatal(err)
		}
		onB := NewAgents(st.Devices())
		onB.SetMasters(fakeMasters{live: map[string]bool{"a": true, "b": true}, srv: u}, routes)
		if err := onB.CheckUpgrade(ctx, "dev-1"); !errors.Is(err, tt.wantErr) {
			t.Fatalf("minor %d: forwarded CheckUpgrade = %v, want %v", tt.minor, err, tt.wantErr)
		}
		res, err := onB.Upgrade(ctx, "dev-1", &agentv1.UpgradeRequest{Version: "v1.2.0"})
		if !errors.Is(err, tt.wantErr) || (err == nil && (!res.GetOk() || res.GetVersion() != "v1.2.0")) {
			t.Fatalf("minor %d: forwarded Upgrade = %v, %v", tt.minor, res, err)
		}
	}
}
