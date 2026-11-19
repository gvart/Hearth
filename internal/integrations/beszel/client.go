// SPDX-License-Identifier: AGPL-3.0-only

// Package beszel reads the systems a Beszel hub monitors, with their status
// and current CPU, memory and disk use, over Beszel's PocketBase REST API.
// It only reads.
//
// Each read logs in as a Beszel user with its email and password
// (POST /api/collections/users/auth-with-password) and lists the systems
// that user can see (GET /api/collections/systems/records). A read-only
// Beszel user is enough. The password and the auth token are never logged
// or put in an error.
package beszel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// maxBody caps a response the hub will read.
	maxBody = 16 << 20
	// perPage is the page size of a systems listing.
	perPage = 200
	// maxPages caps a listing: 20 000 systems.
	maxPages = 100
	// maxField caps a name or other text Beszel reports.
	maxField = 255
)

// Statuses of a system, as Beszel names them.
const (
	StatusUp      = "up"
	StatusDown    = "down"
	StatusPaused  = "paused"
	StatusPending = "pending"
)

// System is one system Beszel monitors.
type System struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Host is the address Beszel reaches the system's agent at: an IP
	// address or a hostname.
	Host string `json:"host"`
	// Status is StatusUp, StatusDown, StatusPaused or StatusPending.
	Status string `json:"status"`
	// CPU, Memory and Disk are percentages in use; Disk is the root
	// filesystem.
	CPU    float64 `json:"cpu"`
	Memory float64 `json:"memory"`
	Disk   float64 `json:"disk"`
	// Uptime is in seconds.
	Uptime       uint64 `json:"uptime"`
	AgentVersion string `json:"agent_version"`
}

// Client reads one Beszel hub.
type Client struct {
	base     *url.URL
	email    string
	password string
	hc       *http.Client
}

// New returns a client for the Beszel hub at rawURL, e.g.
// http://beszel.lan:8090, logging in as email with password. A nil hc uses
// a client with a 10 s timeout.
func New(rawURL, email, password string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse beszel url: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("beszel url %q: want http(s)://host[:port]", rawURL)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("beszel url: no user, query or fragment; pass the password with HEARTH_BESZEL_PASSWORD")
	}
	if email == "" || password == "" {
		return nil, errors.New("beszel: an email and a password are required")
	}
	u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/api")
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{base: u, email: email, password: password, hc: hc}, nil
}

// Target names the Beszel hub in the audit log and logs. It holds no
// secret.
func (c *Client) Target() string { return "beszel:" + c.base.String() }

// record is a record of the systems collection, as the API returns it.
type record struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Host   string `json:"host"`
	Status string `json:"status"`
	Info   struct {
		Uptime       uint64  `json:"u"`
		CPU          float64 `json:"cpu"`
		MemPct       float64 `json:"mp"`
		DiskPct      float64 `json:"dp"`
		AgentVersion string  `json:"v"`
	} `json:"info"`
}

type listResponse struct {
	Page       int      `json:"page"`
	TotalPages int      `json:"totalPages"`
	Items      []record `json:"items"`
}

// Systems logs in and returns every system the user can see, by name.
func (c *Client) Systems(ctx context.Context) ([]System, error) {
	token, err := c.login(ctx)
	if err != nil {
		return nil, err
	}
	var out []System
	for page := 1; page <= maxPages; page++ {
		q := url.Values{
			"page":    {strconv.Itoa(page)},
			"perPage": {strconv.Itoa(perPage)},
			"fields":  {"id,name,host,status,info"},
		}
		var res listResponse
		if err := c.do(ctx, http.MethodGet, "/api/collections/systems/records", q, token, nil, &res); err != nil {
			return nil, fmt.Errorf("beszel systems: %w", err)
		}
		for _, r := range res.Items {
			out = append(out, System{
				ID: clip(r.ID), Name: clip(r.Name), Host: clip(r.Host), Status: clip(r.Status),
				CPU: pct(r.Info.CPU), Memory: pct(r.Info.MemPct), Disk: pct(r.Info.DiskPct),
				Uptime: r.Info.Uptime, AgentVersion: clip(r.Info.AgentVersion),
			})
		}
		if page >= res.TotalPages || len(res.Items) == 0 {
			break
		}
	}
	return out, nil
}

// clip trims s and cuts it to maxField bytes.
func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxField {
		s = s[:maxField]
	}
	return s
}

// pct clamps a percentage to 0..100.
func pct(v float64) float64 { return min(max(v, 0), 100) }

// login authenticates as the user and returns its token.
func (c *Client) login(ctx context.Context) (string, error) {
	body, err := json.Marshal(map[string]string{"identity": c.email, "password": c.password})
	if err != nil {
		return "", fmt.Errorf("beszel login: %w", err)
	}
	var res struct {
		Token string `json:"token"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/collections/users/auth-with-password", nil, "", body, &res); err != nil {
		return "", fmt.Errorf("beszel login: %w", err)
	}
	if res.Token == "" {
		return "", errors.New("beszel login: no token in the response")
	}
	return res.Token, nil
}

// apiError is PocketBase's error body.
type apiError struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// do sends one request and decodes a 2xx JSON response into out. Errors
// name the status and PocketBase's message, never the request.
func (c *Client) do(ctx context.Context, method, path string, q url.Values, token string, body []byte, out any) error {
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = q.Encode()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		// PocketBase takes the token as is, without a scheme.
		req.Header.Set("Authorization", token)
	}
	resp, err := c.hc.Do(req)
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
			msg += ": " + clip(e.Message)
		}
		if token == "" && body != nil && resp.StatusCode == http.StatusBadRequest {
			msg += " (wrong email or password?)"
		}
		return errors.New(msg)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
