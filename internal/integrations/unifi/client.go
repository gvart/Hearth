// SPDX-License-Identifier: AGPL-3.0-only

// Package unifi adopts UniFi Network controllers (a UniFi OS console or a
// self-hosted Network application) through the Network application's API:
// it reads the site's devices (gateways, switches and access points), its
// clients (wired and wireless) and its health (WAN and the rest), feeds the
// clients to network discovery, and restarts an access point only through
// policy (unifi.ap.restart, dangerous).
//
// A UniFi OS console is reached under /proxy/network, with an API key
// (X-API-KEY) or a local login (the TOKEN cookie and an X-CSRF-Token); a
// self-hosted controller with a local login (the unifises cookie). Every
// mode reads the same /api/s/<site>/ endpoints.
//
// The password, the API key, the session cookie and the CSRF token are
// sealed or held in memory only: they are never logged, put in an error or
// served by the API.
package unifi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	// requestTimeout bounds one request, from dial to the end of the body.
	requestTimeout = 10 * time.Second
	dialTimeout    = 5 * time.Second
	// maxBody caps a response the hub will read.
	maxBody = 8 << 20
	// osPrefix is where a UniFi OS console serves the Network application.
	osPrefix = "/proxy/network"
)

var (
	// ErrBadLogin is returned when the controller refuses the username and
	// password, or the API key.
	ErrBadLogin = errors.New("the controller refused the login")
	// errForbidden is an endpoint the account may not use: a read-only or
	// limited admin.
	errForbidden = errors.New("not allowed for this account (403)")
	// errMissing is an endpoint the controller does not have.
	errMissing = errors.New("not on this controller (404)")
	// errUnauthorized is a request the controller answered 401: an expired
	// session, or a refused API key.
	errUnauthorized = errors.New("unauthorized (401)")
	errBadJSON      = errors.New("the controller's answer is not the JSON it should be")
)

// client calls one controller's Network API. With a login it logs in on the
// first call, and again once a read when the controller no longer knows the
// session.
type client struct {
	root string // https://host:port
	base string // root, or root + /proxy/network on UniFi OS
	kind string
	site string
	key  string
	user string
	pass string
	hc   *http.Client

	mu      sync.Mutex
	cookies []*http.Cookie
	csrf    string
}

func newClient(c Connection) (*client, error) {
	tlsCfg, err := tlsConfig(c)
	if err != nil {
		return nil, err
	}
	base := c.URL
	if c.Kind == KindUniFiOS {
		base += osPrefix
	}
	return &client{
		root: c.URL, base: base, kind: c.Kind, site: c.Site,
		key: c.APIKey, user: c.Username, pass: c.Password,
		hc: &http.Client{
			Timeout: requestTimeout,
			// A redirect could carry the credentials somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
				TLSClientConfig:       tlsCfg,
				TLSHandshakeTimeout:   dialTimeout,
				ResponseHeaderTimeout: requestTimeout,
				MaxIdleConnsPerHost:   1,
				IdleConnTimeout:       time.Minute,
			},
		},
	}, nil
}

func (c *client) close() { c.hc.CloseIdleConnections() }

// requestError drops the URL an http.Client error starts with.
func requestError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// envelope is the Network API's answer: {"meta": {"rc": "ok"}, "data": [...]}.
type envelope struct {
	Meta struct {
		RC  string `json:"rc"`
		Msg string `json:"msg"`
	} `json:"meta"`
	Data json.RawMessage `json:"data"`
}

// do makes one request to the site's path (such as /stat/device) and decodes
// its data into out, if not nil.
func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/api/s/"+url.PathEscape(c.site)+path, rd)
	if err != nil {
		return errors.New("build request")
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.key != "" {
		req.Header.Set("X-API-KEY", c.key)
	} else {
		c.mu.Lock()
		for _, ck := range c.cookies {
			req.AddCookie(ck)
		}
		if c.csrf != "" {
			req.Header.Set("X-CSRF-Token", c.csrf)
		}
		c.mu.Unlock()
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return requestError(err)
	}
	defer resp.Body.Close()
	// UniFi OS rotates the CSRF token on some answers.
	if t := resp.Header.Get("X-Updated-Csrf-Token"); t != "" && c.key == "" {
		c.mu.Lock()
		c.csrf = t
		c.mu.Unlock()
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return requestError(err)
	}
	var env envelope
	jsonErr := json.Unmarshal(raw, &env)
	if env.Meta.Msg == "api.err.NoSiteContext" {
		return fmt.Errorf("the controller has no site %q: give the site's short name, as in /network/<name>/ or /manage/site/<name>/", c.site)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return errUnauthorized
	case resp.StatusCode == http.StatusForbidden:
		return errForbidden
	case resp.StatusCode == http.StatusNotFound:
		return errMissing
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Errorf("the controller answered %d, a redirect: check the URL and whether it is a UniFi OS console", resp.StatusCode)
	case resp.StatusCode != http.StatusOK && env.Meta.Msg != "":
		return fmt.Errorf("the controller answered %d (%s)", resp.StatusCode, clip(env.Meta.Msg))
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("the controller answered %d", resp.StatusCode)
	case jsonErr != nil:
		return errBadJSON
	case env.Meta.RC != "ok":
		return fmt.Errorf("the controller answered an error (%s)", clip(env.Meta.Msg))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return errBadJSON
	}
	return nil
}

// login opens a session: the UniFi OS login (/api/auth/login), or the
// classic one (/api/login).
func (c *client) login(ctx context.Context) error {
	path := "/api/login"
	if c.kind == KindUniFiOS {
		path = "/api/auth/login"
	}
	b, err := json.Marshal(map[string]any{"username": c.user, "password": c.pass})
	if err != nil {
		return errors.New("encode login")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.root+path, bytes.NewReader(b))
	if err != nil {
		return errors.New("build login")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("log in: %w", requestError(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrBadLogin
	case resp.StatusCode == http.StatusTooManyRequests:
		return errors.New("log in: the controller is limiting logins for now; Hearth tries again")
	case resp.StatusCode == http.StatusNotFound || (resp.StatusCode >= 300 && resp.StatusCode < 400):
		if c.kind == KindUniFiOS {
			return errors.New("log in: no UniFi OS login here: is this a self-hosted controller?")
		}
		return errors.New("log in: no controller login here: is this a UniFi OS console?")
	default:
		return fmt.Errorf("log in: the controller answered %d", resp.StatusCode)
	}
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return fmt.Errorf("log in: %w", errBadJSON)
	}
	c.mu.Lock()
	c.cookies, c.csrf = cookies, resp.Header.Get("X-Csrf-Token")
	c.mu.Unlock()
	return nil
}

func (c *client) loggedIn() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cookies) > 0
}

func (c *client) logout() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cookies, c.csrf = nil, ""
}

// batch is a run of calls (one read, one action) that logs in again at most
// once between them.
type batch struct {
	c        *client
	relogged bool
}

func (c *client) batch() *batch { return &batch{c: c} }

// call makes one request. With an API key a 401 is a refused key. With a
// login, the first 401 of a batch logs in again, as the session may have
// expired; a 401 right after a login is a refusal.
func (b *batch) call(ctx context.Context, method, path string, body, out any) error {
	c := b.c
	if c.key != "" {
		err := c.do(ctx, method, path, body, out)
		if errors.Is(err, errUnauthorized) {
			return ErrBadLogin
		}
		return err
	}
	if !c.loggedIn() {
		if err := c.login(ctx); err != nil {
			return err
		}
		b.relogged = true
	}
	err := c.do(ctx, method, path, body, out)
	if errors.Is(err, errUnauthorized) && !b.relogged {
		b.relogged = true
		c.logout()
		if err := c.login(ctx); err != nil {
			return err
		}
		err = c.do(ctx, method, path, body, out)
	}
	if errors.Is(err, errUnauthorized) {
		return errors.New("the controller refused a fresh session")
	}
	return err
}
