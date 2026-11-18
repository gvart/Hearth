// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

const (
	defaultWebhookTimeout = 10 * time.Second
	maxWebhookTimeout     = time.Minute
	// maxWebhookDrain is how much of a response body is read, so the
	// connection can be reused; the rest is discarded with the connection.
	maxWebhookDrain = 64 << 10
)

// webhookAction sends one HTTP request from the hub.
type webhookAction struct {
	client  *http.Client
	method  string
	url     string
	headers map[string]string
	body    string
	timeout time.Duration
	// site is the URL without path, query or user info: webhook URLs often
	// carry their secret there, so only site is ever logged or audited.
	site string
}

func buildWebhook(p Params, client *http.Client) (Action, error) {
	var cfg struct {
		URL     string            `yaml:"url"`
		Method  string            `yaml:"method"`
		Headers map[string]string `yaml:"headers"`
		Body    string            `yaml:"body"`
		Timeout time.Duration     `yaml:"timeout"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("url must be an http:// or https:// URL")
	}
	method := strings.ToUpper(cfg.Method)
	if method == "" {
		method = http.MethodPost
	}
	if strings.ContainsFunc(method, func(r rune) bool { return r < 'A' || r > 'Z' }) {
		return nil, fmt.Errorf("method %q is not an HTTP method", cfg.Method)
	}
	switch {
	case cfg.Timeout == 0:
		cfg.Timeout = defaultWebhookTimeout
	case cfg.Timeout < 0 || cfg.Timeout > maxWebhookTimeout:
		return nil, fmt.Errorf("timeout must be between 0 and %s", maxWebhookTimeout)
	}
	return &webhookAction{
		client: client, method: method, url: cfg.URL, headers: cfg.Headers, body: cfg.Body,
		timeout: cfg.Timeout, site: u.Scheme + "://" + u.Host,
	}, nil
}

func newWebhookRequest(ctx context.Context, method, rawURL string, headers map[string]string, body string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func (a *webhookAction) Describe() string      { return fmt.Sprintf("send %s %s/…", a.method, a.site) }
func (a *webhookAction) Policy() policy.Action { return policy.AutomationWebhook }
func (a *webhookAction) Target() string        { return a.site }

// Run sends the request. Any 2xx answer is success. Errors name the site
// only: never the full URL, headers or body, which may hold secrets.
func (a *webhookAction) Run(ctx context.Context, _ Event) error {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	req, err := newWebhookRequest(ctx, a.method, a.url, a.headers, a.body)
	if err != nil {
		return fmt.Errorf("webhook %s: invalid request", a.site)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // url.Error repeats the full URL
		}
		return fmt.Errorf("webhook %s %s: %w", a.method, a.site, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxWebhookDrain))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook %s %s answered %s", a.method, a.site, resp.Status)
	}
	return nil
}
