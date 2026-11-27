// SPDX-License-Identifier: AGPL-3.0-only

package ai

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := []struct {
		name, in string
		// gone must not survive; kept must.
		gone, kept []string
	}{
		{
			name: "private key",
			in:   "key:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\nAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----\nafter",
			gone: []string{"b3BlbnNzaC1rZXktdjEAAAA", "AAAABG5vbmU="}, kept: []string{"key:", "after", "[REDACTED PEM BLOCK]"},
		},
		{
			name: "certificate",
			in:   "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ\n-----END CERTIFICATE-----",
			gone: []string{"MIIBszCCAVmgAwIBAgIUQ"},
		},
		{
			name: "cut off PEM",
			in:   "x -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA",
			gone: []string{"MIIEowIBAAKCAQEA"}, kept: []string{"x "},
		},
		{
			name: "authorization header",
			in:   "GET / Authorization: Bearer abc.def.ghi-123 200",
			gone: []string{"abc.def.ghi-123"}, kept: []string{"Authorization: ", "200"},
		},
		{
			name: "basic auth header",
			in:   "authorization=Basic dXNlcjpwYXNz",
			gone: []string{"dXNlcjpwYXNz"},
		},
		{
			name: "bearer in prose",
			in:   "curl -H 'x: bearer s3cr3tTOKENvalue' http://h",
			gone: []string{"s3cr3tTOKENvalue"}, kept: []string{"http://h"},
		},
		{
			name: "url credentials",
			in:   "connecting to postgres://app:hunter2@db:5432/app",
			gone: []string{"hunter2"}, kept: []string{"postgres://app:", "@db:5432/app"},
		},
		{
			name: "hearth tokens",
			in:   "join with hearth1.Zm9vYmFyYmF6cXV4.YWJjZGVm and hearthj1.c2VjcmV0.ZmluZ2Vy and hearth_mcp_0123456789abcdefXYZ",
			gone: []string{"Zm9vYmFyYmF6cXV4", "c2VjcmV0", "hearth_mcp_0123456789abcdefXYZ"}, kept: []string{"join with"},
		},
		{
			name: "api keys",
			in:   "sk-ant-api03-AbCdEfGhIjKlMnOpQrSt ghp_0123456789abcdefghijABCDEFGHIJ AKIAABCDEFGHIJKLMNOP xoxb-1234567890-abcdef",
			gone: []string{"AbCdEfGhIjKlMnOpQrSt", "ghp_0123456789", "AKIAABCDEFGHIJKLMNOP", "xoxb-1234567890"},
		},
		{
			name: "jwt",
			in:   "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
			gone: []string{"eyJzdWIiOiIxMjM0NTY3ODkwIn0"},
		},
		{
			name: "env and yaml",
			in:   "DB_PASSWORD=hunter2\napi_key: abc123\nGRAFANA_ADMIN_PASSWD='p w'\nclient_secret = xyz",
			gone: []string{"hunter2", "abc123", "p w", "xyz"}, kept: []string{"DB_PASSWORD=", "api_key: ", "client_secret = "},
		},
		{
			name: "json",
			in:   `{"user": "bob", "password": "pa ss", "access_token": "t0k"}`,
			gone: []string{"pa ss", "t0k"}, kept: []string{`"user": "bob"`},
		},
		{
			name: "x-api-key header",
			in:   "X-Api-Key: 9f8e7d6c",
			gone: []string{"9f8e7d6c"},
		},
		{
			name: "ssh public key",
			in:   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host",
			gone: []string{"AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"}, kept: []string{"user@host"},
		},
		{
			name: "plain log",
			in:   "nginx: worker process exited on signal 9 (OOM)\ndisk /dev/sda1 98% full",
			kept: []string{"nginx: worker process exited on signal 9 (OOM)", "disk /dev/sda1 98% full"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Redact(c.in)
			for _, g := range c.gone {
				if strings.Contains(r.Text, g) {
					t.Errorf("%q survived: %q", g, r.Text)
				}
			}
			for _, k := range c.kept {
				if !strings.Contains(r.Text, k) {
					t.Errorf("%q lost: %q", k, r.Text)
				}
			}
			if len(c.gone) > 0 && r.Count == 0 {
				t.Error("nothing counted")
			}
			if len(c.gone) == 0 && r.Count != 0 {
				t.Errorf("count = %d for a clean text: %q", r.Count, r.Text)
			}
			// Redacting again changes nothing.
			if again := Redact(r.Text); again.Text != r.Text || again.Count != 0 {
				t.Errorf("not idempotent: %q -> %q (%d)", r.Text, again.Text, again.Count)
			}
		})
	}
}

func TestPrepareExplain(t *testing.T) {
	long := strings.Repeat("line of log\n", 2000) + "the newest line password=hunter2\n"
	p := PrepareExplain(Explain{
		Subject:  "device pi",
		Question: "why is it slow? my token: abc",
		Sections: []Section{
			{ID: "facts", Title: "Facts", Body: "os: linux"},
			{ID: "log", Title: "Log", Body: long, KeepTail: true},
		},
	}, 4096)
	if len(p.Request.Messages) != 1 || p.Request.System == "" {
		t.Fatalf("request = %+v", p.Request)
	}
	text := p.Request.Messages[0].Content
	if len(text) > 4096+512 {
		t.Errorf("sent %d bytes", len(text))
	}
	for _, want := range []string{"device pi", "[facts]", "os: linux", "[log]", "the newest line password=" + Mask, "my token: " + Mask} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(text, "hunter2") || strings.Contains(text, ": abc") {
		t.Error("a secret was sent")
	}
	if p.Redactions != 2 || len(p.Truncated) != 1 || p.Truncated[0] != "log" {
		t.Errorf("redactions %d, truncated %v", p.Redactions, p.Truncated)
	}

	if q := PrepareExplain(Explain{Subject: "d"}, 0); !strings.Contains(q.Request.Messages[0].Content, DefaultQuestion) {
		t.Error("no default question")
	}
}
