// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/pki"
)

// TestJoinWithAHubToken: a token naming its hub (an AP cluster master)
// enrolls there whatever hub URL is given, and through the given URL when
// the named hub cannot be reached.
func TestJoinWithAHubToken(t *testing.T) {
	h := startHub(t)
	const dead = "https://127.0.0.1:1"
	for name, urls := range map[string][2]string{
		"named hub":       {h.url, dead},
		"given hub after": {dead, h.url},
	} {
		t.Run(name, func(t *testing.T) {
			tok := h.token(t, time.Now().Add(15*time.Minute))
			id, err := agent.Join(t.Context(), urls[1], tok.EncodeHub(urls[0]), filepath.Join(t.TempDir(), "agent"), "pi")
			if err != nil {
				t.Fatalf("Join: %v", err)
			}
			if _, err := h.st.Devices().Get(t.Context(), id); err != nil {
				t.Fatalf("device not stored: %v", err)
			}
		})
	}
}

// TestJoinHubFromToken: with no hub URL given, Join enrolls with the hub the
// token names and stores that URL.
func TestJoinHubFromToken(t *testing.T) {
	h := startHub(t)
	dataDir := filepath.Join(t.TempDir(), "agent")
	tok := h.token(t, time.Now().Add(time.Minute))
	id, err := agent.Join(t.Context(), "", tok.EncodeHub(h.url), dataDir, "pi")
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if _, err := h.st.Devices().Get(t.Context(), id); err != nil {
		t.Fatalf("device not stored: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dataDir, agent.HubURLFile)); err != nil || string(b) != h.url+"\n" {
		t.Errorf("%s = %q (%v), want %s", agent.HubURLFile, b, err, h.url)
	}
}

// TestJoinHubFromTokenRejected: a token used for its hub alone is still
// single use and expires; a token without a hub, or with a hub URL that is
// garbled, not https, or swapped for another hub's, fails, and the secret
// never reaches a hub whose CA is not the pinned one.
func TestJoinHubFromTokenRejected(t *testing.T) {
	h := startHub(t)
	other := startHub(t)
	tests := []struct {
		name     string
		token    func(t *testing.T) (string, pki.Token)
		wantCode connect.Code
		wantErr  error
		wantMsg  string
		unspent  bool // the token must still be unconsumed at h
	}{
		{name: "expired", token: func(t *testing.T) (string, pki.Token) {
			tok := h.token(t, time.Now().Add(-time.Second))
			return tok.EncodeHub(h.url), tok
		}, wantCode: connect.CodeUnauthenticated},
		{name: "reused", token: func(t *testing.T) (string, pki.Token) {
			tok := h.token(t, time.Now().Add(time.Minute))
			if _, err := agent.Join(t.Context(), "", tok.EncodeHub(h.url), t.TempDir(), "first"); err != nil {
				t.Fatalf("first Join: %v", err)
			}
			return tok.EncodeHub(h.url), tok
		}, wantCode: connect.CodeUnauthenticated},
		{name: "no hub in token", token: func(t *testing.T) (string, pki.Token) {
			tok := h.token(t, time.Now().Add(time.Minute))
			return tok.Encode(), tok
		}, wantMsg: "the token names no hub", unspent: true},
		{name: "garbled hub URL", token: func(t *testing.T) (string, pki.Token) {
			tok := h.token(t, time.Now().Add(time.Minute))
			s := tok.EncodeHub(h.url)
			return s[:strings.LastIndexByte(s, '.')] + ".!!", tok
		}, wantMsg: "malformed hub URL", unspent: true},
		{name: "plain-http hub URL", token: func(t *testing.T) (string, pki.Token) {
			tok := h.token(t, time.Now().Add(time.Minute))
			return tok.EncodeHub("http" + strings.TrimPrefix(h.url, "https")), tok
		}, wantMsg: "hub URL must be https://", unspent: true},
		{name: "hub URL swapped for another hub", token: func(t *testing.T) (string, pki.Token) {
			tok := h.token(t, time.Now().Add(time.Minute))
			return tok.EncodeHub(other.url), tok
		}, wantErr: pki.ErrFingerprintMismatch, unspent: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, tok := tt.token(t)
			dataDir := filepath.Join(t.TempDir(), "agent")
			_, err := agent.Join(t.Context(), "", s, dataDir, "pi")
			if err == nil {
				t.Fatal("Join succeeded, want error")
			}
			if tt.wantCode != 0 && connect.CodeOf(err) != tt.wantCode {
				t.Errorf("code = %v (%v), want %v", connect.CodeOf(err), err, tt.wantCode)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("err = %v, want %q", err, tt.wantMsg)
			}
			if strings.Contains(err.Error(), tok.Secret) {
				t.Errorf("error echoes the secret: %v", err)
			}
			if _, statErr := os.Stat(filepath.Join(dataDir, agent.CertFile)); statErr == nil {
				t.Error("failed Join wrote an identity")
			}
			if tt.unspent {
				if _, err := h.st.Tokens().Consume(t.Context(), tok.Secret, time.Now()); err != nil {
					t.Errorf("token was spent despite the failure: %v", err)
				}
			}
		})
	}
	// The other hub never got an enrollment request: the pin failed in the
	// TLS handshake, before the secret was sent.
	if entries, err := other.st.Audit().List(t.Context(), 10); err != nil || len(entries) != 0 {
		t.Errorf("other hub audit = %+v, %v; want nothing", entries, err)
	}
}
