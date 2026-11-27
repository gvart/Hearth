// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CeilingAppliedWithin bounds how long after a PUT of a device's capabilities
// its agent reports them: the hub pushes them at once to an agent streaming
// to it, and the agent sends its facts as soon as it has applied them.
const CeilingAppliedWithin = 5 * time.Second

// e2eLogLine is what the journalctl stub in the e2e image prints (Dockerfile).
const e2eLogLine = "hearth e2e log line"

// turnLogsOn turns logs on for a device from the hub, for an agent started with
// no flags, and streams a log from it with no restart (#346).
func (s *stack) turnLogsOn(ctx context.Context, c *apiClient, id string) {
	s.t.Helper()
	at := time.Now()
	if err := c.put(ctx, "/api/v1/devices/"+id+"/capabilities",
		map[string]any{"hub": map[string]any{"logs": []string{"systemd:*"}}}); err != nil {
		s.t.Fatalf("turn logs on: %v", err)
	}
	waitFor(ctx, s.t, at.Add(CeilingAppliedWithin), "logs in effect", func() (bool, string) {
		var caps struct {
			Effective *struct {
				Logs []string `json:"logs"`
			} `json:"effective"`
		}
		if err := c.get(ctx, "/api/v1/devices/"+id+"/capabilities", &caps); err != nil {
			return false, err.Error()
		}
		if caps.Effective == nil || len(caps.Effective.Logs) == 0 {
			return false, "effective ceiling has no logs"
		}
		return true, ""
	})
	s.t.Logf("logs turned on from the hub, applied in %v", since(at))

	streamCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	q := url.Values{"source": {"systemd:e2e.service"}, "tail": {"10"}}
	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, c.base+"/api/v1/devices/"+id+"/logs?"+q.Encode(), nil)
	if err != nil {
		s.t.Fatal(err)
	}
	// The client's 5 s timeout would cut the stream: streamCtx bounds it.
	resp, err := (&http.Client{Jar: c.http.Jar}).Do(req)
	if err != nil {
		s.t.Fatalf("stream logs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.t.Fatalf("stream logs: %s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if strings.Contains(sc.Text(), e2eLogLine) {
			s.t.Logf("streamed a log line %v after turning logs on", since(at))
			return
		}
	}
	s.t.Fatalf("log stream ended without %q: %v", e2eLogLine, sc.Err())
}

func (c *apiClient) put(ctx context.Context, path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, nil)
}

func (c *apiClient) get(ctx context.Context, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return fmt.Errorf("get %s: %w", path, err)
	}
	return c.do(req, into)
}
