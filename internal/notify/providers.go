// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// telegramAPI is the Telegram Bot API.
const telegramAPI = "https://api.telegram.org"

// newNtfy returns a channel that publishes to topic on the ntfy server at
// server, with an optional access token.
func newNtfy(server, topic, token string) (channel, error) {
	u, err := url.Parse(server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return channel{}, errors.New("url must be the ntfy server's http:// or https:// URL")
	}
	if u.User != nil || u.RawQuery != "" || strings.Trim(u.Path, "/") != "" {
		return channel{}, errors.New("url must be the server only, as https://ntfy.example.com: put the topic in topic and an access token in token")
	}
	if topic == "" || strings.ContainsAny(topic, "/?# ") {
		return channel{}, errors.New("topic is required, and is one path segment")
	}
	endpoint := strings.TrimSuffix(u.String(), "/") + "/"
	header := http.Header{}
	if token != "" {
		header.Set("Authorization", "Bearer "+token)
	}
	return channel{typ: "ntfy", send: func(ctx context.Context, c *http.Client, m Message) error {
		// JSON publishing carries any UTF-8 title, which a Title header
		// cannot.
		body := map[string]any{"topic": topic, "message": m.Body}
		if m.Title != "" {
			body["title"] = m.Title
		}
		if m.Link != "" {
			label := m.LinkLabel
			if label == "" {
				label = "Open"
			}
			body["click"] = m.Link
			body["actions"] = []map[string]any{{"action": "view", "label": label, "url": m.Link, "clear": true}}
		}
		return post(ctx, c, endpoint, header, body, func(b []byte) string { return field(b, "error") })
	}}, nil
}

// newTelegram returns a channel that sends to chatID through the bot with
// botToken, using the Bot API at api.
func newTelegram(api, botToken, chatID string) (channel, error) {
	if botToken == "" || strings.ContainsAny(botToken, "/?# ") {
		return channel{}, errors.New("bot_token is required: the token @BotFather gave the bot")
	}
	if chatID == "" {
		return channel{}, errors.New("chat_id is required: the chat's id, or @channelname")
	}
	endpoint := api + "/bot" + botToken + "/sendMessage"
	return channel{typ: "telegram", send: func(ctx context.Context, c *http.Client, m Message) error {
		text := m.Body
		if m.Title != "" {
			text = m.Title + "\n" + m.Body
		}
		if m.Link != "" {
			text += "\n" + m.Link
		}
		// Plain text: no parse_mode, so template values need no escaping.
		body := map[string]string{"chat_id": chatID, "text": text}
		return post(ctx, c, endpoint, nil, body, func(b []byte) string { return field(b, "description") })
	}}, nil
}
