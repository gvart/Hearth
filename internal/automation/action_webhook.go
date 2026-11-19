// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
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
	headers map[string]Text
	body    Text
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
	// The URL is not a template: it often holds the secret, and only its
	// site may be logged, which a rendered URL would make unknowable.
	headers := make(map[string]Text, len(cfg.Headers))
	for k, v := range cfg.Headers {
		if headers[k], err = p.Text(v, "headers", k); err != nil {
			return nil, err
		}
	}
	body, err := p.Text(cfg.Body, "body")
	if err != nil {
		return nil, err
	}
	return &webhookAction{
		client: client, method: method, url: cfg.URL, headers: headers, body: body,
		timeout: cfg.Timeout, site: u.Scheme + "://" + u.Host,
	}, nil
}

// newWebhookRequest renders the headers and body for ev. Errors never hold
// their values, which may be secrets.
func newWebhookRequest(ctx context.Context, method, rawURL string, headers map[string]Text, body Text, ev Event) (*http.Request, error) {
	b, err := body.Render(ctx, ev)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(b))
	if err != nil {
		return nil, errors.New("invalid request")
	}
	for k, v := range headers {
		h, err := v.Render(ctx, ev)
		if err != nil {
			return nil, err
		}
		req.Header.Set(k, h)
	}
	return req, nil
}

func (a *webhookAction) texts() []Text {
	out := []Text{a.body}
	for _, k := range slices.Sorted(maps.Keys(a.headers)) {
		out = append(out, a.headers[k])
	}
	return out
}

func (a *webhookAction) Describe() string      { return fmt.Sprintf("send %s %s/…", a.method, a.site) }
func (a *webhookAction) Policy() policy.Action { return policy.AutomationWebhook }
func (a *webhookAction) Target() Text          { return Literal(a.site) }

// Run sends the request. Any 2xx answer is success. Errors name the site
// only: never the full URL, headers or body, which may hold secrets. An error
// wraps ErrOutcomeUnknown unless the request certainly did nothing: the first
// hop could not be reached, or the target itself answered with a refusal. A
// write answered 504 is not a refusal: the target may still act on it.
func (a *webhookAction) Run(ctx context.Context, ev Event) error {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	var connected atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { connected.Store(true) },
	})
	req, err := newWebhookRequest(ctx, a.method, a.url, a.headers, a.body, ev)
	if err != nil {
		return fmt.Errorf("webhook %s: %w", a.site, err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // url.Error repeats the full URL
		}
		if !connected.Load() && unreachable(err) {
			return fmt.Errorf("webhook %s %s: %w", a.method, a.site, err)
		}
		return fmt.Errorf("webhook %s %s: %w: %w", a.method, a.site, err, ErrOutcomeUnknown)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxWebhookDrain))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if resp.Request != nil && resp.Request.Response != nil {
			// An earlier hop took the request before sending it on.
			return fmt.Errorf("webhook %s %s answered %s after a redirect: %w", a.method, a.site, resp.Status, ErrOutcomeUnknown)
		}
		if resp.StatusCode == http.StatusGatewayTimeout && isWrite(a.method) {
			// A gateway gave up waiting for the target, which may still act.
			return fmt.Errorf("webhook %s %s answered %s: %w", a.method, a.site, resp.Status, ErrOutcomeUnknown)
		}
		return fmt.Errorf("webhook %s %s answered %s", a.method, a.site, resp.Status)
	}
	return nil
}

// isWrite reports whether method changes what it is sent to.
func isWrite(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// unreachable reports whether err is a failure to find or dial a host.
func unreachable(err error) bool {
	var op *net.OpError
	var dns *net.DNSError
	return (errors.As(err, &op) && op.Op == "dial") || errors.As(err, &dns)
}
