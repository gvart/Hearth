// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSendMessageLink(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	n, err := Parse([]byte("channels:\n  phone:\n    type: ntfy\n    url: " + srv.URL + "\n    topic: lab\n"))
	if err != nil {
		t.Fatal(err)
	}
	link := "https://hub.lan:8443/#/approve/abc"
	if err := n.SendMessage(context.Background(), "phone", Message{Title: "t", Body: "b", Link: link, LinkLabel: "Review"}); err != nil {
		t.Fatal(err)
	}
	actions, _ := got["actions"].([]any)
	if got["click"] != link || len(actions) != 1 {
		t.Fatalf("ntfy body = %v", got)
	}
	a, _ := actions[0].(map[string]any)
	if a["action"] != "view" || a["label"] != "Review" || a["url"] != link {
		t.Errorf("ntfy action = %v", a)
	}

	ch, err := newTelegram(srv.URL, "123:SECRET", "-100")
	if err != nil {
		t.Fatal(err)
	}
	n = &Notifier{client: srv.Client(), channels: map[string]channel{"family": ch}}
	if err := n.SendMessage(context.Background(), "family", Message{Title: "t", Body: "b", Link: link}); err != nil {
		t.Fatal(err)
	}
	if got["text"] != "t\nb\n"+link {
		t.Errorf("telegram text = %q", got["text"])
	}
}

// fake records the requests a provider fake gets and answers them.
type fake struct {
	mu     sync.Mutex
	reqs   []recorded
	status int
	answer string
}

type recorded struct {
	path, auth string
	body       map[string]string
}

func newFake(t *testing.T, status int, answer string) (*fake, *httptest.Server) {
	t.Helper()
	f := &fake{status: status, answer: answer}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body map[string]string
		if err := json.Unmarshal(b, &body); err != nil || r.Header.Get("Content-Type") != "application/json" || r.Method != http.MethodPost {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{path: r.URL.Path, auth: r.Header.Get("Authorization"), body: body})
		f.mu.Unlock()
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, f.answer)
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fake) only(t *testing.T) recorded {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(f.reqs))
	}
	return f.reqs[0]
}

func TestNtfySend(t *testing.T) {
	tests := []struct {
		name, token, title string
		wantAuth           string
		wantBody           map[string]string
	}{
		{
			"with title and token", "tk_secret", "nas is offline", "Bearer tk_secret",
			map[string]string{"topic": "lab", "title": "nas is offline", "message": "since 10:00 ✓"},
		},
		{
			"no title, no token", "", "", "",
			map[string]string{"topic": "lab", "message": "since 10:00 ✓"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, srv := newFake(t, http.StatusOK, `{"id":"x"}`)
			cfg := "channels:\n  phone:\n    type: ntfy\n    url: " + srv.URL + "/\n    topic: lab\n"
			if tt.token != "" {
				cfg += "    token: " + tt.token + "\n"
			}
			n, err := Parse([]byte(cfg))
			if err != nil {
				t.Fatal(err)
			}
			if err := n.Send(context.Background(), "phone", tt.title, "since 10:00 ✓"); err != nil {
				t.Fatal(err)
			}
			got := f.only(t)
			if got.path != "/" || got.auth != tt.wantAuth {
				t.Errorf("path %q auth %q, want / and %q", got.path, got.auth, tt.wantAuth)
			}
			if len(got.body) != len(tt.wantBody) {
				t.Errorf("body = %v, want %v", got.body, tt.wantBody)
			}
			for k, v := range tt.wantBody {
				if got.body[k] != v {
					t.Errorf("body[%s] = %q, want %q", k, got.body[k], v)
				}
			}
		})
	}
}

func TestTelegramSend(t *testing.T) {
	f, srv := newFake(t, http.StatusOK, `{"ok":true}`)
	ch, err := newTelegram(srv.URL, "123:SECRET", "-100")
	if err != nil {
		t.Fatal(err)
	}
	n := &Notifier{client: srv.Client(), channels: map[string]channel{"family": ch}}
	if err := n.Send(context.Background(), "family", "nas is offline", "since 10:00"); err != nil {
		t.Fatal(err)
	}
	got := f.only(t)
	if got.path != "/bot123:SECRET/sendMessage" {
		t.Errorf("path = %q", got.path)
	}
	if got.body["chat_id"] != "-100" || got.body["text"] != "nas is offline\nsince 10:00" || got.body["parse_mode"] != "" {
		t.Errorf("body = %v", got.body)
	}
}

// TestSendErrorsHideSecrets checks that a failed send names the channel and
// the provider's reason, never the token, topic or server address.
func TestSendErrorsHideSecrets(t *testing.T) {
	_, telegramDown := newFake(t, http.StatusUnauthorized, `{"ok":false,"description":"Unauthorized"}`)
	_, ntfyDenied := newFake(t, http.StatusForbidden, `{"code":40301,"error":"forbidden"}`)
	unreachable := httptest.NewServer(http.NotFoundHandler())
	unreachable.Close()

	tests := []struct {
		name    string
		ch      func() (channel, error)
		wantErr string
	}{
		{
			"telegram rejects the token", func() (channel, error) { return newTelegram(telegramDown.URL, "123:SECRET", "-100") },
			"notify ch (telegram): answered 401 Unauthorized: Unauthorized",
		},
		{
			"ntfy denies the topic", func() (channel, error) { return newNtfy(ntfyDenied.URL, "secret-topic", "tk_SECRET") },
			"notify ch (ntfy): answered 403 Forbidden: forbidden",
		},
		{
			"telegram unreachable", func() (channel, error) { return newTelegram(unreachable.URL, "123:SECRET", "-100") },
			"notify ch (telegram): ",
		},
		{
			"ntfy unreachable", func() (channel, error) { return newNtfy(unreachable.URL, "secret-topic", "tk_SECRET") },
			"notify ch (ntfy): ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, err := tt.ch()
			if err != nil {
				t.Fatal(err)
			}
			n := &Notifier{client: &http.Client{}, channels: map[string]channel{"ch": ch}}
			err = n.Send(context.Background(), "ch", "t", "m")
			if err == nil || !strings.HasPrefix(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want prefix %q", err, tt.wantErr)
			}
			for _, secret := range []string{"SECRET", "secret-topic", "/bot", "sendMessage"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error %q holds %q", err, secret)
				}
			}
		})
	}
}

func TestSendUnknownChannel(t *testing.T) {
	for _, n := range []*Notifier{nil, {}} {
		if err := n.Send(context.Background(), "phone", "", "m"); !errors.Is(err, ErrNoChannel) {
			t.Errorf("err = %v, want ErrNoChannel", err)
		}
		if n.Has("phone") || len(n.Channels()) != 0 {
			t.Error("an empty notifier has channels")
		}
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name, cfg string
		want      []ChannelInfo
		wantErr   string
	}{
		{"empty file", "", []ChannelInfo{}, ""},
		{"both kinds, sorted", `
channels:
  phone: {type: ntfy, url: "https://ntfy.lan", topic: hearth}
  family: {type: telegram, bot_token: "1:AA", chat_id: "-1"}
`, []ChannelInfo{{"family", "telegram"}, {"phone", "ntfy"}}, ""},
		{"unknown type", "channels:\n  x: {type: slack}\n", nil, "channel x: type must be ntfy or telegram"},
		{"bad name", "channels:\n  Phone: {type: ntfy, url: \"https://n\", topic: t}\n", nil, "name must be"},
		{"unknown field", "channels:\n  x: {type: ntfy, url: \"https://n\", topic: t, priority: 5}\n", nil, "priority"},
		{"ntfy topic in url", "channels:\n  x: {type: ntfy, url: \"https://n/SECRET\", topic: t}\n", nil, "url must be the server only"},
		{"ntfy token in url", "channels:\n  x: {type: ntfy, url: \"https://u:SECRET@n\", topic: t}\n", nil, "url must be the server only"},
		{"ntfy no topic", "channels:\n  x: {type: ntfy, url: \"https://n\"}\n", nil, "topic is required"},
		{"ntfy bad url", "channels:\n  x: {type: ntfy, url: \"ntfy.lan\", topic: t}\n", nil, "url must be"},
		{"ntfy with telegram fields", "channels:\n  x: {type: ntfy, url: \"https://n\", topic: t, chat_id: \"1\"}\n", nil, "are for telegram"},
		{"telegram no token", "channels:\n  x: {type: telegram, chat_id: \"1\"}\n", nil, "bot_token is required"},
		{"telegram no chat", "channels:\n  x: {type: telegram, bot_token: \"1:SECRET\"}\n", nil, "chat_id is required"},
		{"telegram with ntfy fields", "channels:\n  x: {type: telegram, bot_token: \"1:SECRET\", chat_id: \"1\", token: SECRET}\n", nil, "are for ntfy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := Parse([]byte(tt.cfg))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				if strings.Contains(err.Error(), "SECRET") {
					t.Errorf("error %q quotes a secret", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := n.Channels()
			if len(got) != len(tt.want) {
				t.Fatalf("channels = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("channels = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestLoadAndExposed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.yaml")
	if _, err := Load(path); err == nil {
		t.Fatal("missing file loaded")
	}
	if err := os.WriteFile(path, []byte("channels:\n  p: {type: ntfy, url: \"https://n\", topic: t}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := Load(path)
	if err != nil || !n.Has("p") {
		t.Fatalf("Load = %v, %v", n, err)
	}
	if Exposed(path) {
		t.Error("a 0600 file is exposed")
	}
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // the test makes the file exposed on purpose
		t.Fatal(err)
	}
	if !Exposed(path) {
		t.Error("a 0644 file is not exposed")
	}
}
