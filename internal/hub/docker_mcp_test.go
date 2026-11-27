// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gvart/hearth/internal/mcpserver"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

type mcpBearer string

func (b mcpBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(r)
}

// mcpDockerCall calls an MCP tool as the safe token "assistant", through the
// hub's real Agents to a fake agent of dev-1 reporting ceiling, and returns
// its text, whether it is a tool error, what the agent got, and the Docker
// audit entries as "actor decision action target result".
func mcpDockerCall(t *testing.T, ceiling *agentv1.Ceiling, tool string, args map[string]any) (string, bool, []*agentv1.DockerRequest, []string) {
	t.Helper()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClient(t, st)
	reqs := fakeDockerAgent(connectAgent(t.Context(), t, client, minDockerMinor, ceiling), dockerAnswer)
	if err := st.MCPTokens().Create(t.Context(), "assistant", "assistant-token", string(policy.Safe), time.Now()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mcpserver.Handler(mcpserver.Config{
		Devices: st.Devices(), Tokens: st.MCPTokens(), Policy: policy.New(st.Audit()), Agents: agents,
		Log: slog.New(slog.DiscardHandler),
	}))
	t.Cleanup(srv.Close)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint: srv.URL + mcpserver.Path, HTTPClient: &http.Client{Transport: mcpBearer("assistant-token")},
		MaxRetries: -1, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	// Wait for the agent's stream to attach.
	for i := 0; errors.Is(agents.CheckDocker(t.Context(), "dev-1", &agentv1.DockerRequest{}), ErrAgentNotConnected); i++ {
		if i == 100 {
			t.Fatal("the agent never attached")
		}
		time.Sleep(10 * time.Millisecond)
	}
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	var got []*agentv1.DockerRequest
	for len(reqs) > 0 {
		got = append(got, <-reqs)
	}
	es, err := st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var audit []string
	for _, e := range es {
		if strings.HasPrefix(e.Action, "device.docker.") {
			audit = append(audit, e.ActorKind+"/"+e.ActorID+" "+e.Decision+" "+e.Action+" "+e.Target+" "+e.Result)
		}
	}
	return b.String(), res.IsError, got, audit
}

// The MCP Docker tools take the web API's path: the agent's reported
// ceiling, policy and the audit log apply, as mcp/<token>.
func TestMCPDocker(t *testing.T) {
	t.Parallel()
	on := &agentv1.Ceiling{Docker: true}
	restart := map[string]any{"device": "dev-1", "container": "web", "action": "restart"}
	for _, tc := range []struct {
		name    string
		ceiling *agentv1.Ceiling
		tool    string
		args    map[string]any
		isErr   bool
		want    string
		sent    bool
		audited string
	}{
		{"list", on, "list_containers", map[string]any{"device": "dev-1"}, false, "media-web-1", true, "allow device.docker.list dev-1"},
		{"restart", on, "container_action", restart, false, "succeeded", true, "allow device.docker.restart dev-1 ok"},
		{
			"outside the ceiling", &agentv1.Ceiling{Restart: []string{"docker:web"}}, "container_action", restart,
			true, "ceiling", false, "deny device.docker.restart dev-1",
		},
		{
			"logs outside the ceiling", nil, "container_logs",
			map[string]any{"device": "dev-1", "container": "web"},
			true, "ceiling", false, "deny device.docker.logs dev-1",
		},
		{"unknown device", on, "list_containers", map[string]any{"device": "nas"}, true, "nas", false, "allow device.docker.list nas error"},
		{
			"unknown container", on, "container_action",
			map[string]any{"device": "dev-1", "container": "gone", "action": "stop"},
			true, "No such container: gone", true, "allow device.docker.stop dev-1 error",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			text, isErr, sent, audit := mcpDockerCall(t, tc.ceiling, tc.tool, tc.args)
			if isErr != tc.isErr || !strings.Contains(text, tc.want) {
				t.Errorf("%s = %q (error %v), want %q", tc.tool, text, isErr, tc.want)
			}
			if (len(sent) > 0) != tc.sent {
				t.Errorf("agent got %v, want a request: %v", sent, tc.sent)
			}
			if len(audit) != 1 || !strings.HasPrefix(audit[0], "mcp/assistant "+tc.audited) {
				t.Errorf("audit = %q, want one %q", audit, tc.audited)
			}
		})
	}
}
