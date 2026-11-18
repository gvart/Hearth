// SPDX-License-Identifier: AGPL-3.0-only

// Package notify sends notifications to named channels: an ntfy topic or a
// Telegram chat. Channels and their credentials are configured in a file on
// the hub, and are referred to everywhere else (automations, the API, the
// audit log) by name only, so no secret leaves that file.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// sendTimeout bounds one notification.
const sendTimeout = 10 * time.Second

// maxAnswer is how much of a provider's answer is read.
const maxAnswer = 64 << 10

// ErrNoChannel is returned for a channel name that is not configured.
var ErrNoChannel = errors.New("no such notification channel")

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// ChannelInfo is what may be shown about a channel: never its credentials or
// address.
type ChannelInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Notifier sends to the configured channels. The zero value has none.
type Notifier struct {
	client   *http.Client
	channels map[string]channel
}

type channel struct {
	typ  string
	send func(ctx context.Context, c *http.Client, m Message) error
}

// Message is one notification.
type Message struct {
	// Title may be empty.
	Title string
	Body  string
	// Link, when set, is a URL the notification opens: ntfy shows it as a
	// button labelled LinkLabel and opens it on a tap; Telegram gets it on
	// a line of its own.
	Link      string
	LinkLabel string
}

// Load reads the channels file at path. A missing file is an error.
func Load(path string) (*Notifier, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read notification channels: %w", err)
	}
	n, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return n, nil
}

// Exposed says whether users other than the owner of the file at path may
// read it: it holds credentials.
func Exposed(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().Perm()&fs.FileMode(0o044) != 0
}

// Parse reads a channels file:
//
//	channels:
//	  phone:
//	    type: ntfy
//	    url: https://ntfy.example.com
//	    topic: hearth
//	    token: tk_...            # optional
//	  family:
//	    type: telegram
//	    bot_token: "123456:ABC..."
//	    chat_id: "-1001234567890"
//
// Errors never quote a value: values are credentials.
func Parse(b []byte) (*Notifier, error) {
	var file struct {
		Channels map[string]struct {
			Type     string `yaml:"type"`
			URL      string `yaml:"url"`
			Topic    string `yaml:"topic"`
			Token    string `yaml:"token"`
			BotToken string `yaml:"bot_token"`
			ChatID   string `yaml:"chat_id"`
		} `yaml:"channels"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse: %w", err)
	}
	n := &Notifier{client: &http.Client{}, channels: map[string]channel{}}
	for name, c := range file.Channels {
		if !nameRE.MatchString(name) {
			return nil, fmt.Errorf("channel %q: name must be lowercase letters, digits, - and _", name)
		}
		var (
			ch  channel
			err error
		)
		switch c.Type {
		case "ntfy":
			if c.BotToken != "" || c.ChatID != "" {
				return nil, fmt.Errorf("channel %s: bot_token and chat_id are for telegram", name)
			}
			ch, err = newNtfy(c.URL, c.Topic, c.Token)
		case "telegram":
			if c.URL != "" || c.Topic != "" || c.Token != "" {
				return nil, fmt.Errorf("channel %s: url, topic and token are for ntfy", name)
			}
			ch, err = newTelegram(telegramAPI, c.BotToken, c.ChatID)
		default:
			err = errors.New("type must be ntfy or telegram")
		}
		if err != nil {
			return nil, fmt.Errorf("channel %s: %w", name, err)
		}
		n.channels[name] = ch
	}
	return n, nil
}

// Channels lists the channels by name.
func (n *Notifier) Channels() []ChannelInfo {
	out := []ChannelInfo{}
	if n == nil {
		return out
	}
	for name, c := range n.channels {
		out = append(out, ChannelInfo{Name: name, Type: c.typ})
	}
	slices.SortFunc(out, func(a, b ChannelInfo) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Has says whether channel is configured.
func (n *Notifier) Has(channel string) bool {
	if n == nil {
		return false
	}
	_, ok := n.channels[channel]
	return ok
}

// Send sends a notification to channel. title may be empty. Errors name the
// channel and its type, never its topic or credentials; a connection error
// may name the server's host and port.
func (n *Notifier) Send(ctx context.Context, channel, title, message string) error {
	return n.SendMessage(ctx, channel, Message{Title: title, Body: message})
}

// SendMessage sends m to channel, as Send does.
func (n *Notifier) SendMessage(ctx context.Context, channel string, m Message) error {
	if n == nil {
		return fmt.Errorf("%w %q", ErrNoChannel, channel)
	}
	c, ok := n.channels[channel]
	if !ok {
		return fmt.Errorf("%w %q", ErrNoChannel, channel)
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	if err := c.send(ctx, n.client, m); err != nil {
		return fmt.Errorf("notify %s (%s): %w", channel, c.typ, err)
	}
	return nil
}

// post sends a JSON body and checks the answer. Errors hold neither the URL,
// which may carry a token, nor the body; only describe's reading of a failed
// answer.
func post(ctx context.Context, c *http.Client, rawURL string, header http.Header, body any, describe func([]byte) string) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(b))
	if err != nil {
		return errors.New("invalid request")
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // url.Error repeats the full URL
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if why := describe(answer); why != "" {
			return fmt.Errorf("answered %s: %s", resp.Status, why)
		}
		return fmt.Errorf("answered %s", resp.Status)
	}
	return nil
}

// field returns a string field of a JSON object, cut short.
func field(b []byte, key string) string {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	s, _ := m[key].(string)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
