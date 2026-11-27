// SPDX-License-Identifier: AGPL-3.0-only

// Package opnsense adopts OPNsense firewalls through their REST API, with an
// API key and secret as HTTP basic auth over https: it reads the system info
// and firmware status, the DHCP leases (ISC dhcpd, Kea and dnsmasq), the ARP
// and NDP tables and the interfaces' traffic counters, feeds the clients to
// network discovery, and restarts Unbound only through policy
// (opnsense.unbound.restart, dangerous).
//
// The key and the secret are sealed or held in memory only: they are never
// logged, put in an error or served by the API.
package opnsense

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// requestTimeout bounds one API request, from dial to the end of the body.
	requestTimeout = 10 * time.Second
	dialTimeout    = 5 * time.Second
	// maxBody caps a response the hub will read.
	maxBody = 4 << 20
)

var (
	// ErrBadLogin is returned when the firewall refuses the API key or secret.
	ErrBadLogin = errors.New("the firewall refused the API key or secret")
	// errDenied is an endpoint the key's user has no privilege for.
	errDenied = errors.New("not allowed by the API key's privileges")
	// errMissing is an endpoint the firewall does not have: a plugin that is
	// not installed, or an older OPNsense.
	errMissing = errors.New("not on this firewall")
)

// client calls one firewall's API. There is no session: every request
// carries the key and secret.
type client struct {
	base   string
	key    string
	secret string
	hc     *http.Client
}

func newClient(c Connection) (*client, error) {
	tlsCfg, err := tlsConfig(c)
	if err != nil {
		return nil, err
	}
	return &client{
		base:   c.URL,
		key:    c.Key,
		secret: c.Secret,
		hc: &http.Client{
			Timeout: requestTimeout,
			// A redirect could carry the key somewhere else.
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

// get reads path and decodes its JSON answer into out.
func (c *client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, out)
}

// post calls path with an empty JSON object, as the web GUI does: OPNsense
// refuses a JSON request with an empty body.
func (c *client) post(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodPost, path, out)
}

func (c *client) do(ctx context.Context, method, path string, out any) error {
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader("{}")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return fmt.Errorf("%s: build request", path)
	}
	req.SetBasicAuth(c.key, c.secret)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", path, requestError(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("%s: %w", path, requestError(err))
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrBadLogin
	case resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%s: %w", path, errDenied)
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%s: %w", path, errMissing)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Errorf("%s: the firewall answered %d, a redirect: check the URL and port of the web GUI", path, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("%s: the firewall answered %d", path, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s: the firewall's answer has an unexpected form", path)
	}
	return nil
}

// restartUnbound restarts the DNS resolver. OPNsense answers "OK" once its
// configd ran the restart.
func (c *client) restartUnbound(ctx context.Context) error {
	var out struct {
		Response json.RawMessage `json:"response"`
	}
	if err := c.post(ctx, pathRestartDNS, &out); err != nil {
		return err
	}
	var text string
	if json.Unmarshal(out.Response, &text) != nil || strings.TrimSpace(text) != "OK" {
		return fmt.Errorf("%s: the firewall did not confirm the restart", pathRestartDNS)
	}
	return nil
}

// requestError drops the URL an http.Client error starts with.
func requestError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
