// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/policy"
)

// runBridge starts a bridge to f as token and returns a function that sends
// one line and, for a request, reads one answer.
func runBridge(t *testing.T, f *fixture, token string) (send func(line string, answer bool) map[string]any, done func()) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		errc <- Bridge(t.Context(), f.url, token, http.DefaultClient, inR, outW, slog.New(slog.DiscardHandler))
		_ = outW.Close()
	}()
	lines := bufio.NewScanner(outR)
	lines.Buffer(nil, maxMessage)
	send = func(line string, answer bool) map[string]any {
		t.Helper()
		if _, err := io.WriteString(inW, line+"\n"); err != nil {
			t.Fatal(err)
		}
		if !answer {
			return nil
		}
		if !lines.Scan() {
			t.Fatalf("no answer to %s: %v", line, lines.Err())
		}
		var m map[string]any
		if err := json.Unmarshal(lines.Bytes(), &m); err != nil {
			t.Fatalf("answer %q: %v", lines.Bytes(), err)
		}
		return m
	}
	done = func() {
		t.Helper()
		_ = inW.Close()
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}
	return send, done
}

func TestBridge(t *testing.T) {
	f := newFixture(t, policy.Config{})
	send, done := runBridge(t, f, "safe-token")
	init := send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`, true)
	if r, _ := init["result"].(map[string]any); r == nil || r["protocolVersion"] == nil {
		t.Fatalf("initialize = %v", init)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, false)
	list := send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, true)
	if !strings.Contains(mustJSON(t, list), "restart_service") {
		t.Fatalf("tools/list = %v", list)
	}
	res := send(`{"jsonrpc":"2.0","id":"three","method":"tools/call","params":{"name":"list_devices","arguments":{}}}`, true)
	if res["id"] != "three" || !strings.Contains(mustJSON(t, res), `pi.lan`) {
		t.Fatalf("tools/call = %v", res)
	}
	done()
	if e := f.lastAudit(t); e.ActorID != "safe" || e.Action != string(policy.DeviceRead) {
		t.Errorf("audit = %+v", e)
	}
}

func TestBridgeBadToken(t *testing.T) {
	f := newFixture(t, policy.Config{})
	send, done := runBridge(t, f, "revoked-token")
	res := send(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`, true)
	e, _ := res["error"].(map[string]any)
	if res["id"] != float64(7) || e == nil || !strings.Contains(e["message"].(string), "refused the MCP token") {
		t.Fatalf("answer = %v", res)
	}
	send(`not json`, false) // no id to answer: dropped
	done()
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
