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
	"google.golang.org/protobuf/proto"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
)

const testArchiveSum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// upgradeFixture is a hub of version v1.2.0 with device dev-1 enrolled.
type upgradeFixture struct {
	*apiFixture
	client agentv1connect.AgentServiceClient
}

func newUpgradeFixture(t *testing.T, version string, pcfg policy.Config) *upgradeFixture {
	t.Helper()
	f := &upgradeFixture{}
	f.apiFixture = newAPIFixture(t, true, withPolicy(pcfg), func(c *Config) {
		f.client, c.Agents = newExecClient(t, c.Store)
		c.Version = version
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

// testArchiveURL is the archive a test agent says it downloaded.
const testArchiveURL = "https://example.com/releases/v1.2.0/hearth_1.2.0_linux_amd64.tar.gz"

func upgraded(req *agentv1.UpgradeRequest) *agentv1.UpgradeResult {
	return &agentv1.UpgradeResult{Ok: true, Version: req.GetVersion(), Url: testArchiveURL, Sha256: testArchiveSum}
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
	// The agent is told the version only: it finds the archive and its
	// checksum in that release itself.
	if req := <-reqs; req.GetVersion() != "v1.2.0" {
		t.Errorf("agent got %v", req)
	}
	entries := auditOf(t, f.apiFixture, policy.DeviceUpgrade)
	if len(entries) != 1 || entries[0].Decision != policy.Allow || entries[0].Target != "dev-1" || entries[0].Result != "ok" {
		t.Fatalf("audit = %+v", entries)
	}
	for _, want := range []string{`"version":"v1.2.0"`, `"from":"v1.0.0"`, `"url":"` + testArchiveURL + `"`, `"sha256":"` + testArchiveSum + `"`} {
		if !strings.Contains(string(entries[0].Detail), want) {
			t.Errorf("audit detail %s lacks %s", entries[0].Detail, want)
		}
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
		{
			name: "re-auth missing", minor: minUpgradeMinor, set: linuxAmd64, noReauth: true,
			status: http.StatusForbidden, code: "reauth_required", audit: policy.Deny,
		},
		{
			name: "policy deny", pcfg: deny, minor: minUpgradeMinor, set: linuxAmd64,
			status: http.StatusForbidden, code: "forbidden", audit: policy.Deny,
		},
		{
			name: "old agent", minor: minUpgradeMinor - 2, set: linuxAmd64,
			status: http.StatusConflict, code: "agent_too_old", audit: policy.Deny,
		},
		{
			name: "kubernetes agent", minor: minUpgradeMinor,
			set: func(h *agentv1.Hello) {
				h.NoSelfUpgrade = "this agent runs in a Kubernetes pod: upgrade its image instead"
			},
			status: http.StatusConflict, code: "cannot_upgrade", audit: policy.Deny,
		},
		{
			name: "agent with --local-ceiling", minor: minUpgradeMinor,
			set: func(h *agentv1.Hello) {
				h.NoSelfUpgrade = "this agent runs with --local-ceiling, so the hub cannot change it: upgrade it on the device with the installer"
			},
			status: http.StatusConflict, code: "cannot_upgrade", audit: policy.Deny,
		},
		{
			name: "dev hub without a version", version: "dev", minor: minUpgradeMinor, set: linuxAmd64,
			status: http.StatusConflict, code: "no_version",
		},
		{
			name: "not a release", minor: minUpgradeMinor, set: linuxAmd64, body: `{"version":"latest"}`,
			status: http.StatusBadRequest, code: "bad_request",
		},
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

// The agent's own failure (a checksum mismatch) is audited as the result,
// with the archive it tried, and its refusal (a downgrade) as a denial.
func TestUpgradeDeviceAgentFails(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		res    *agentv1.UpgradeResult
		status int
		code   string
		want   string
	}{
		{
			name:   "checksum mismatch",
			res:    &agentv1.UpgradeResult{Error: "checksum mismatch: nothing was changed", Url: testArchiveURL, Sha256: testArchiveSum},
			status: http.StatusBadGateway, code: "upgrade_failed", want: "checksum mismatch",
		},
		{
			name:   "unreachable release",
			res:    &agentv1.UpgradeResult{Error: "download https://example.com/x: no route (the device must reach GitHub to upgrade itself)"},
			status: http.StatusBadGateway, code: "upgrade_failed", want: "must reach GitHub",
		},
		{
			name:   "downgrade",
			res:    &agentv1.UpgradeResult{Denied: true, Error: "v1.2.0 is older than the v1.3.0 this agent runs: downgrades are refused"},
			status: http.StatusConflict, code: "cannot_upgrade", want: "downgrades are refused",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newUpgradeFixture(t, "v1.2.0", policy.Config{})
			f.connectUpgrader(t, minUpgradeMinor, linuxAmd64, func(*agentv1.UpgradeRequest) *agentv1.UpgradeResult {
				return proto.Clone(tt.res).(*agentv1.UpgradeResult)
			})
			c := sessionCookie(t, f.login(t, testPassword))
			resp := f.do(t, http.MethodPost, "/api/v1/devices/dev-1/upgrade", "", c)
			if resp.StatusCode != tt.status || errorCode(t, resp) != tt.code || !strings.Contains(string(resp.body), tt.want) {
				t.Fatalf("upgrade = %d %s, want %d %s", resp.StatusCode, resp.body, tt.status, tt.code)
			}
			entries := auditOf(t, f.apiFixture, policy.DeviceUpgrade)
			if len(entries) != 1 || entries[0].Decision != policy.Allow || !strings.Contains(entries[0].Result, tt.want) {
				t.Fatalf("audit = %+v", entries)
			}
			if tt.res.GetUrl() != "" && !strings.Contains(string(entries[0].Detail), tt.res.GetUrl()) {
				t.Errorf("audit detail %s lacks the archive", entries[0].Detail)
			}
		})
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
