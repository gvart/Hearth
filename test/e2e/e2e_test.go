// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

// Package e2e guards Hearth's headline demo end to end: a hub and two agents
// in docker compose (compose.yaml), driven through the hub's JSON API.
//
//	go test -tags e2e ./test/e2e/...   # or: task e2e
//
// It needs the docker CLI with the compose plugin. On failure the hub and
// agent logs are written to HEARTH_E2E_LOG_DIR (default test/e2e/logs).
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// DeviceVisibleWithin is the headline promise: a device that runs
// `hearth agent join` is online in the hub within this long. Never raise it to
// make CI pass.
const DeviceVisibleWithin = 10 * time.Second

const (
	// OfflineWithin bounds how long after an agent stops the hub reports it
	// offline: up to one heartbeat interval (10 s) has passed since the last
	// heartbeat, so the 30 s offline threshold plus a 5 s sweep fit.
	OfflineWithin = 40 * time.Second
	// HubReconnectWithin bounds how long after a hub restart every agent is
	// connected to the new hub process. The old hub ends agent streams as
	// soon as it shuts down and agents retry within 250 ms, so this is mostly
	// the container restart (about 1.3 s locally); the rest is CI headroom.
	HubReconnectWithin = 10 * time.Second
)

const (
	adminPassword = "e2e-admin-password" //nolint:gosec // G101: throwaway test password, matches compose.yaml
	hubAgentURL   = "https://hub:7443"
	agentDataDir  = "/var/lib/hearth/agent"
)

var agents = []string{"agent-1", "agent-2"}

func TestHeadlineDemo(t *testing.T) {
	ctx := t.Context()
	s := newStack(t)

	// 1. Start the stack; --wait returns once the hub healthcheck passes.
	s.compose(ctx, "up", "--detach", "--build", "--wait", "--wait-timeout", "120")
	api := s.login(ctx)

	// 2–4. Enroll each agent and require it online within DeviceVisibleWithin
	// of starting `join`.
	ids := map[string]string{}
	for _, name := range agents {
		token := api.createToken(ctx)
		joinAt := time.Now()
		s.compose(ctx, "exec", "-T", name, "hearth", "agent", "join", hubAgentURL, token, "--data-dir", agentDataDir)
		s.startAgent(ctx, name)
		d := api.waitDevice(ctx, name, joinAt.Add(DeviceVisibleWithin), "online", func(d device) bool {
			return d.Status == "online"
		})
		ids[name] = d.ID
		t.Logf("%s: join → online in %v", name, time.Since(joinAt).Round(time.Millisecond))
	}

	// 5. Stop one agent; the hub must mark it offline.
	stopAt := time.Now()
	s.compose(ctx, "stop", "agent-1")
	api.waitDevice(ctx, "agent-1", stopAt.Add(OfflineWithin), "offline", func(d device) bool {
		return d.Status == "offline"
	})
	t.Logf("agent-1: stop → offline in %v", time.Since(stopAt).Round(time.Millisecond))

	// Bring it back before restarting the hub, so the restart covers both.
	startAt := time.Now()
	s.compose(ctx, "start", "agent-1")
	s.startAgent(ctx, "agent-1")
	api.waitDevice(ctx, "agent-1", startAt.Add(DeviceVisibleWithin), "online", func(d device) bool {
		return d.Status == "online"
	})
	t.Logf("agent-1: restart → online in %v", time.Since(startAt).Round(time.Millisecond))

	// 6. Restart the hub; both agents must reconnect to the new hub process.
	// Device status is persisted, so "online" alone proves nothing: require a
	// last_seen after the new hub container started (one clock: the docker host).
	restartAt := time.Now()
	s.compose(ctx, "restart", "hub")
	hubStarted := s.startedAt(ctx, "hub")
	api = s.login(ctx) // the API port is reassigned on restart
	for _, name := range agents {
		d := api.waitDevice(ctx, name, restartAt.Add(HubReconnectWithin), "reconnected", func(d device) bool {
			return d.Status == "online" && d.LastSeen.After(hubStarted)
		})
		if d.ID != ids[name] {
			t.Errorf("%s: device id changed across hub restart: %s → %s", name, ids[name], d.ID)
		}
	}
	t.Logf("hub restart → both agents reconnected in %v", time.Since(restartAt).Round(time.Millisecond))
}

// stack is one compose project, torn down (with its volumes) when the test ends.
type stack struct {
	t       *testing.T
	project string
}

func newStack(t *testing.T) *stack {
	t.Helper()
	s := &stack{t: t, project: "hearth-e2e-" + strconv.Itoa(os.Getpid())}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if t.Failed() {
			s.dumpLogs(ctx)
		}
		if out, err := s.run(ctx, "down", "--volumes", "--remove-orphans", "--timeout", "2"); err != nil {
			t.Logf("compose down: %v\n%s", err, out)
		}
	})
	return s
}

// run runs `docker compose` on this project and returns its stdout, with
// stderr folded into the error.
func (s *stack) run(ctx context.Context, args ...string) (string, error) {
	args = append([]string{"compose", "--project-name", s.project, "--file", "compose.yaml"}, args...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("docker %s: %w\n%s", strings.Join(redact(args), " "), err, stderr.String())
	}
	return stdout.String(), nil
}

func (s *stack) compose(ctx context.Context, args ...string) string {
	s.t.Helper()
	out, err := s.run(ctx, args...)
	if err != nil {
		s.t.Fatal(err)
	}
	return out
}

// startAgent starts `hearth agent run` in the background inside an agent
// container, with its output on the container's log (PID 1's stdout).
func (s *stack) startAgent(ctx context.Context, name string) {
	s.t.Helper()
	s.compose(ctx, "exec", "--detach", name, "sh", "-c",
		"exec hearth agent run --data-dir "+agentDataDir+" >/proc/1/fd/1 2>&1")
}

// startedAt is when the service's container last started, by the docker
// host's clock (the clock the hub stamps last_seen with).
func (s *stack) startedAt(ctx context.Context, service string) time.Time {
	s.t.Helper()
	id := strings.TrimSpace(s.compose(ctx, "ps", "--quiet", service))
	out, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.StartedAt}}", id).Output()
	if err != nil {
		s.t.Fatalf("inspect %s: %v", service, err)
	}
	ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(out)))
	if err != nil {
		s.t.Fatalf("parse start time of %s: %v", service, err)
	}
	return ts
}

func (s *stack) dumpLogs(ctx context.Context) {
	dir := os.Getenv("HEARTH_E2E_LOG_DIR")
	if dir == "" {
		dir = "logs"
	}
	if err := os.MkdirAll(dir, 0o750); err != nil { //nolint:gosec // G703: the dir is chosen by whoever runs the test
		s.t.Logf("create log dir: %v", err)
		return
	}
	for _, svc := range append([]string{"hub"}, agents...) {
		out, err := s.run(ctx, "logs", "--no-color", "--timestamps", svc)
		if err != nil {
			out += "\n" + err.Error()
		}
		path := filepath.Join(dir, svc+".log")
		if err := os.WriteFile(path, []byte(out), 0o600); err != nil { //nolint:gosec // G703: see MkdirAll above
			s.t.Logf("write %s: %v", path, err)
			continue
		}
		s.t.Logf("wrote %s", path)
	}
}

// redact hides the enrollment token in command lines that end up in errors.
func redact(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if i > 0 && args[i-1] == hubAgentURL {
			a = "<token>"
		}
		out[i] = a
	}
	return out
}

// apiClient is a logged-in client of the hub's JSON API.
type apiClient struct {
	t    *testing.T
	base string
	http *http.Client
}

// login resolves the hub's published API port and logs in, retrying until the
// hub answers (it may still be starting).
func (s *stack) login(ctx context.Context) *apiClient {
	s.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		s.t.Fatal(err)
	}
	c := &apiClient{t: s.t, http: &http.Client{Jar: jar, Timeout: 5 * time.Second}}
	deadline := time.Now().Add(30 * time.Second)
	for {
		addr, err := s.run(ctx, "port", "hub", "7080")
		if err == nil {
			c.base = "http://" + strings.TrimSpace(addr)
			if err = c.post(ctx, "/api/v1/login", map[string]string{"password": adminPassword}, nil); err == nil {
				return c
			}
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("log in to hub: %v", err)
		}
		if err := sleep(ctx, 200*time.Millisecond); err != nil {
			s.t.Fatal(err)
		}
	}
}

func (c *apiClient) post(ctx context.Context, path string, body, into any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, into)
}

func (c *apiClient) do(req *http.Request, into any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %s", req.Method, req.URL.Path, resp.Status)
	}
	if into == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return fmt.Errorf("%s %s: decode: %w", req.Method, req.URL.Path, err)
	}
	return nil
}

func (c *apiClient) createToken(ctx context.Context) string {
	c.t.Helper()
	var tok struct {
		Token string `json:"token"`
	}
	if err := c.post(ctx, "/api/v1/tokens", map[string]string{"ttl": "5m"}, &tok); err != nil {
		c.t.Fatalf("create token: %v", err)
	}
	if tok.Token == "" {
		c.t.Fatal("create token: empty token")
	}
	return tok.Token
}

type device struct {
	ID       string    `json:"id"`
	Hostname string    `json:"hostname"`
	Status   string    `json:"status"`
	LastSeen time.Time `json:"last_seen"`
}

func (c *apiClient) devices(ctx context.Context) ([]device, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/v1/devices", nil)
	if err != nil {
		return nil, err
	}
	var body struct {
		Devices []device `json:"devices"`
	}
	if err := c.do(req, &body); err != nil {
		return nil, err
	}
	return body.Devices, nil
}

// waitDevice polls the device list until the device with this hostname
// satisfies ok, and fails the test if that has not happened by deadline.
func (c *apiClient) waitDevice(ctx context.Context, hostname string, deadline time.Time, want string, ok func(device) bool) device {
	c.t.Helper()
	var last string
	for {
		devs, err := c.devices(ctx)
		switch {
		case err != nil:
			last = err.Error()
		default:
			last = "not listed"
			for _, d := range devs {
				if d.Hostname != hostname {
					continue
				}
				if ok(d) {
					return d
				}
				last = fmt.Sprintf("status %s, last_seen %s", d.Status, d.LastSeen.Format(time.RFC3339Nano))
			}
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("%s not %s by the deadline (%s)", hostname, want, last)
		}
		if err := sleep(ctx, 100*time.Millisecond); err != nil {
			c.t.Fatal(err)
		}
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return errors.Join(errors.New("wait aborted"), ctx.Err())
	case <-time.After(d):
		return nil
	}
}
