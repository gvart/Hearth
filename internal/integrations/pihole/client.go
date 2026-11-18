// SPDX-License-Identifier: AGPL-3.0-only

// Package pihole reads the hosts a Pi-hole knows (its network table and
// its DHCP leases) over the Pi-hole v6 REST API, for network discovery to
// merge with the hosts it scanned (see discovery.Importer). It only reads.
//
// Each read logs in with the password (an app password is best), reads, and
// logs out, so it holds none of Pi-hole's limited API sessions between
// imports. The password and the session ID are never logged or put in an
// error.
package pihole

import (
	"bytes"
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

const (
	// maxBody caps a response the hub will read.
	maxBody = 16 << 20
	// staleAfter drops entries of Pi-hole's network table not seen for
	// longer: Pi-hole keeps them for a year by default.
	staleAfter = 30 * 24 * time.Hour
	// maxDevices and maxAddresses lift the API's defaults (10 devices, 3
	// addresses each).
	maxDevices   = 10000
	maxAddresses = 16
	// sidHeader carries the session ID.
	sidHeader = "X-FTL-SID"
)

// Client reads one Pi-hole. It implements discovery.Source.
type Client struct {
	base     *url.URL
	password string
	hc       *http.Client
	now      func() time.Time
}

// New returns a client for the Pi-hole web server at rawURL, e.g.
// http://pi.hole (the API is under /api). An empty password is for a
// Pi-hole without one. A nil hc uses a client with a 10 s timeout.
func New(rawURL, password string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse pi-hole url: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("pi-hole url %q: want http(s)://host[:port]", rawURL)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("pi-hole url: no user, query or fragment; pass the password with HEARTH_PIHOLE_PASSWORD")
	}
	u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/api")
	u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/admin")
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{base: u, password: password, hc: hc, now: time.Now}, nil
}

// Name implements discovery.Source.
func (*Client) Name() string { return store.SourcePihole }

// Target implements discovery.Source.
func (c *Client) Target() string { return "pihole:" + c.base.String() }

// Records implements discovery.Source: the hosts of Pi-hole's network
// table seen in the last 30 days, and its active DHCP leases.
func (c *Client) Records(ctx context.Context) (_ []discovery.Record, err error) {
	sid := ""
	if c.password != "" {
		if sid, err = c.login(ctx); err != nil {
			return nil, err
		}
		defer c.logout(ctx, sid)
	}
	var devs devicesResponse
	q := url.Values{"max_devices": {fmt.Sprint(maxDevices)}, "max_addresses": {fmt.Sprint(maxAddresses)}}
	if err := c.do(ctx, http.MethodGet, "/api/network/devices?"+q.Encode(), sid, nil, &devs); err != nil {
		return nil, fmt.Errorf("pi-hole network devices: %w", err)
	}
	var leases leasesResponse
	if err := c.do(ctx, http.MethodGet, "/api/dhcp/leases", sid, nil, &leases); err != nil {
		return nil, fmt.Errorf("pi-hole dhcp leases: %w", err)
	}
	now := c.now()
	var out []discovery.Record
	for _, d := range devs.Devices {
		if r, ok := d.record(now); ok {
			out = append(out, r)
		}
	}
	for _, l := range leases.Leases {
		if l.Expires != 0 && l.Expires < now.Unix() {
			continue
		}
		out = append(out, discovery.Record{MAC: l.HWAddr, IP: l.IP, Hostname: l.Name, Lease: true})
	}
	return out, nil
}

// device is an entry of GET /api/network/devices.
type device struct {
	HWAddr    string  `json:"hwaddr"`
	LastQuery int64   `json:"lastQuery"`
	MACVendor *string `json:"macVendor"`
	IPs       []struct {
		IP       string  `json:"ip"`
		Name     *string `json:"name"`
		LastSeen int64   `json:"lastSeen"`
	} `json:"ips"`
}

type devicesResponse struct {
	Devices []device `json:"devices"`
}

// record is d as a discovery.Record: its most recently seen IPv4 address,
// that address's name (else the newest name of any address), seen at its
// last query or address sighting, whichever is later. A device with no
// IPv4 address, or seen more than staleAfter ago, is none.
func (d device) record(now time.Time) (discovery.Record, bool) {
	var (
		r        discovery.Record
		lastIP   int64 = -1
		nameSeen int64 = -1
		ipName   string
	)
	for _, a := range d.IPs {
		name := ""
		if a.Name != nil {
			name = *a.Name
		}
		if name != "" && a.LastSeen > nameSeen {
			r.Hostname, nameSeen = name, a.LastSeen
		}
		if !strings.Contains(a.IP, ".") || strings.Contains(a.IP, ":") {
			continue // not IPv4
		}
		if a.LastSeen > lastIP {
			r.IP, lastIP, ipName = a.IP, a.LastSeen, name
		}
	}
	if r.IP == "" {
		return discovery.Record{}, false
	}
	if ipName != "" {
		r.Hostname = ipName
	}
	seen := max(d.LastQuery, lastIP)
	if seen <= 0 || now.Sub(time.Unix(seen, 0)) > staleAfter {
		return discovery.Record{}, false
	}
	r.MAC, r.Seen = d.HWAddr, time.Unix(seen, 0).UTC()
	if d.MACVendor != nil {
		r.Vendor = *d.MACVendor
	}
	return r, true
}

// lease is an entry of GET /api/dhcp/leases.
type lease struct {
	Expires int64  `json:"expires"`
	Name    string `json:"name"`
	HWAddr  string `json:"hwaddr"`
	IP      string `json:"ip"`
}

type leasesResponse struct {
	Leases []lease `json:"leases"`
}

type authResponse struct {
	Session struct {
		Valid bool   `json:"valid"`
		SID   string `json:"sid"`
	} `json:"session"`
}

// login opens a session and returns its ID.
func (c *Client) login(ctx context.Context) (string, error) {
	body, err := json.Marshal(map[string]string{"password": c.password})
	if err != nil {
		return "", fmt.Errorf("pi-hole login: %w", err)
	}
	var res authResponse
	if err := c.do(ctx, http.MethodPost, "/api/auth", "", body, &res); err != nil {
		return "", fmt.Errorf("pi-hole login: %w", err)
	}
	if !res.Session.Valid || res.Session.SID == "" {
		return "", errors.New("pi-hole login: no session (two-factor authentication on? use an app password)")
	}
	return res.Session.SID, nil
}

// logout ends the session sid, freeing its API seat. A failure only
// leaves the session to time out.
func (c *Client) logout(ctx context.Context, sid string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = c.do(ctx, http.MethodDelete, "/api/auth", sid, nil, nil)
}

// apiError is Pi-hole's error body.
type apiError struct {
	Error struct {
		Key     string `json:"key"`
		Message string `json:"message"`
	} `json:"error"`
}

// do sends one request and decodes a 2xx JSON response into out (if not
// nil). Errors name the status and Pi-hole's error key and message, never
// the request.
func (c *Client) do(ctx context.Context, method, path, sid string, body []byte, out any) error {
	ref, err := url.Parse(path)
	if err != nil {
		return err
	}
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + ref.Path
	u.RawQuery = ref.RawQuery
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd) //nolint:gosec // the operator-configured Pi-hole URL
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if sid != "" {
		req.Header.Set(sidHeader, sid)
	}
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
		if e.Error.Key != "" {
			msg += ": " + e.Error.Key
			if e.Error.Message != "" {
				msg += ": " + e.Error.Message
			}
		}
		if resp.StatusCode == http.StatusUnauthorized && path == "/api/auth" && method == http.MethodPost {
			msg += " (wrong password?)"
		}
		return errors.New(msg)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
