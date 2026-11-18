// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/policy"
)

func TestProtocol(t *testing.T) {
	f := newFixture(t, policy.Config{})
	tests := []struct {
		name       string
		method     string
		origin     string
		body       string
		wantStatus int
		want       string
	}{
		{
			"initialize picks the client's version", http.MethodPost, "",
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, 200, `"protocolVersion":"2025-06-18"`,
		},
		{
			"initialize offers the newest otherwise", http.MethodPost, "",
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`, 200, `"protocolVersion":"` + protocolVersions[0] + `"`,
		},
		{"ping", http.MethodPost, "", `{"jsonrpc":"2.0","id":"p","method":"ping"}`, 200, `"result":{}`},
		{"notification", http.MethodPost, "", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, 202, ""},
		{"unknown method", http.MethodPost, "", `{"jsonrpc":"2.0","id":2,"method":"resources/list"}`, 200, `-32601`},
		{"unknown tool", http.MethodPost, "", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec_command"}}`, 200, `-32602`},
		{
			"bad arguments", http.MethodPost, "",
			`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_device","arguments":{"nope":1}}}`, 200, `"isError":true`,
		},
		{"parse error", http.MethodPost, "", `{`, 200, `-32700`},
		{"not 2.0", http.MethodPost, "", `{"jsonrpc":"1.0","id":5,"method":"ping"}`, 200, `-32600`},
		{"cross-origin", http.MethodPost, "http://evil.example", `{"jsonrpc":"2.0","id":6,"method":"ping"}`, 403, ""},
		{"no stream to open", http.MethodGet, "", "", 405, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(t.Context(), tt.method, f.url, strings.NewReader(tt.body))
			req.Header.Set("Authorization", "Bearer safe-token")
			req.Header.Set("Content-Type", "application/json")
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if res.StatusCode != tt.wantStatus || !strings.Contains(string(b), tt.want) {
				t.Fatalf("status %d, body %s; want %d with %s", res.StatusCode, b, tt.wantStatus, tt.want)
			}
		})
	}
}
