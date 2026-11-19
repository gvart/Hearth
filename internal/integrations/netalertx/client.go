// SPDX-License-Identifier: AGPL-3.0-only

// Package netalertx reads the devices a NetAlertX knows over its REST API
// (GET /devices on the API server, port GRAPHQL_PORT), for network discovery
// to merge with the hosts it scanned (see discovery.Importer). It only reads.
//
// The API token goes in the Authorization header, never the URL, and is
// never logged or put in an error.
package netalertx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/store"
)

// maxBody caps a response the hub will read.
const maxBody = 16 << 20

// Client reads one NetAlertX. It implements discovery.Source.
type Client struct {
	base  *url.URL
	token string
	hc    *http.Client
	now   func() time.Time
}

// New returns a client for the NetAlertX API server at rawURL, e.g.
// http://netalertx.lan:20212. A nil hc uses a client with a 10 s timeout.
func New(rawURL, token string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse netalertx url: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("netalertx url %q: want http(s)://host[:port]", rawURL)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("netalertx url: no user, query or fragment; pass the token with HEARTH_NETALERTX_TOKEN")
	}
	if token == "" {
		return nil, errors.New("netalertx: an API token is required")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{base: u, token: token, hc: hc, now: time.Now}, nil
}

// Name implements discovery.Source.
func (*Client) Name() string { return store.SourceNetAlertX }

// Target implements discovery.Source.
func (c *Client) Target() string { return "netalertx:" + c.base.String() }

// device is an entry of GET /devices: a row of NetAlertX's Devices table.
type device struct {
	MAC             string `json:"devMac"`
	Name            string `json:"devName"`
	LastIP          string `json:"devLastIP"`
	PrimaryIPv4     string `json:"devPrimaryIPv4"`
	Vendor          string `json:"devVendor"`
	PresentLastScan *int   `json:"devPresentLastScan"`
	Archived        *int   `json:"devIsArchived"`
}

type devicesResponse struct {
	Success bool     `json:"success"`
	Devices []device `json:"devices"`
}

// Records implements discovery.Source: every device NetAlertX has not
// archived. A device present in NetAlertX's last scan counts as seen now;
// NetAlertX's own timestamps are not used, as their time zone depends on
// its version and settings.
func (c *Client) Records(ctx context.Context) ([]discovery.Record, error) {
	var res devicesResponse
	if err := c.get(ctx, "/devices", &res); err != nil {
		return nil, fmt.Errorf("netalertx devices: %w", err)
	}
	if !res.Success {
		return nil, errors.New("netalertx devices: success is false")
	}
	now := c.now().UTC()
	out := make([]discovery.Record, 0, len(res.Devices))
	for _, d := range res.Devices {
		if d.Archived != nil && *d.Archived == 1 {
			continue
		}
		ip := d.LastIP
		if ip == "" {
			ip = d.PrimaryIPv4
		}
		r := discovery.Record{MAC: d.MAC, IP: ip, Hostname: deviceName(d.Name), Vendor: d.Vendor}
		if d.PresentLastScan != nil && *d.PresentLastScan == 1 {
			r.Seen = now
		}
		out = append(out, r)
	}
	return out, nil
}

// deviceName returns name, or "" for the placeholders NetAlertX stores for
// a device whose name it could not find, so they never replace a real one.
func deviceName(name string) string {
	switch n := strings.TrimSpace(name); n {
	case "(unknown)", "(name not found)", "(Unknown)":
		return ""
	default:
		return n
	}
}

// apiError is NetAlertX's error body.
type apiError struct {
	Message string `json:"message"`
	Error   string `json:"error"`
}

// get sends one GET and decodes a 2xx JSON response into out. Errors name
// the status and NetAlertX's message, never the token.
func (c *Client) get(ctx context.Context, path string, out any) error {
	u := *c.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil) //nolint:gosec // the operator-configured NetAlertX URL
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.hc.Do(req) //nolint:gosec // as above
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		var e apiError
		_ = json.Unmarshal(b, &e)
		msg := fmt.Sprintf("HTTP %d", resp.StatusCode)
		if e.Message != "" {
			msg += ": " + e.Message
		}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			msg += " (wrong API token?)"
		}
		return errors.New(msg)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
