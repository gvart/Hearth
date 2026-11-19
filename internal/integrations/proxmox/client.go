// SPDX-License-Identifier: AGPL-3.0-only

// Package proxmox adopts Proxmox VE servers through an API token: it reads
// their nodes, VMs, LXC containers and storage, and starts, stops and reboots
// guests, each action decided by policy and audited.
//
// The token is sealed before it reaches the store and never leaves this
// package in the clear: it is not logged, put in an error or served by the
// API. TLS is always verified, against the system roots, a configured CA or a
// pinned certificate fingerprint.
package proxmox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// defaultPort is where Proxmox VE serves its API.
	defaultPort = "8006"
	// requestTimeout bounds one API request, from dial to the end of the body.
	requestTimeout = 15 * time.Second
	dialTimeout    = 5 * time.Second
	// maxBody caps a response the hub will read: the resources of a large
	// cluster are well under this.
	maxBody = 8 << 20
	// maxMessage caps the part of an error message taken from the server.
	maxMessage = 200
	// statusNodeUnreachable is what Proxmox VE answers when the node it
	// should proxy a request to is down.
	statusNodeUnreachable = 595
)

// ErrBadConnection is returned for a connection that cannot be used. Its
// messages never include the token.
var ErrBadConnection = errors.New("invalid proxmox connection")

// Connection is how the hub reaches one server: what is sealed in the store.
type Connection struct {
	URL string `json:"url"`
	// Token is the API token, USER@REALM!TOKENID=SECRET.
	Token string `json:"token"`
	// CAPEM trusts these certificates instead of the system roots.
	CAPEM string `json:"ca_pem,omitempty"`
	// Fingerprint pins the server's certificate: its SHA-256, lowercase hex.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// TLS modes, as the API names them.
const (
	TLSSystem      = "system"
	TLSCA          = "ca"
	TLSFingerprint = "fingerprint"
)

// tlsMode names how c verifies the server.
func (c Connection) tlsMode() string {
	switch {
	case c.Fingerprint != "":
		return TLSFingerprint
	case c.CAPEM != "":
		return TLSCA
	}
	return TLSSystem
}

func badConnection(msg string) error { return fmt.Errorf("%w: %s", ErrBadConnection, msg) }

// normalize checks c and returns it in its stored form.
func (c Connection) normalize() (Connection, error) {
	var err error
	if c.URL, err = normalizeURL(c.URL); err != nil {
		return Connection{}, err
	}
	if c.Token, err = normalizeToken(c.Token); err != nil {
		return Connection{}, err
	}
	c.CAPEM = strings.TrimSpace(c.CAPEM)
	c.Fingerprint = strings.TrimSpace(c.Fingerprint)
	if c.CAPEM != "" && c.Fingerprint != "" {
		return Connection{}, badConnection("set a CA certificate or a fingerprint, not both")
	}
	if c.CAPEM != "" {
		if _, err := caPool(c.CAPEM); err != nil {
			return Connection{}, err
		}
	}
	if c.Fingerprint != "" {
		if c.Fingerprint, err = normalizeFingerprint(c.Fingerprint); err != nil {
			return Connection{}, err
		}
	}
	return c, nil
}

// normalizeURL returns the server's address as https://host:port.
func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", badConnection("the URL cannot be parsed")
	}
	if u.Scheme != "https" || u.Hostname() == "" {
		return "", badConnection("the URL must be https://host[:port]: the API token is never sent in the clear")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return "", badConnection("the URL must be only https://host[:port]")
	}
	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	return "https://" + net.JoinHostPort(u.Hostname(), port), nil
}

// normalizeToken checks that raw has the form of an API token, with or
// without the header's PVEAPIToken= prefix.
func normalizeToken(raw string) (string, error) {
	const form = "the API token must look like user@realm!tokenid=secret"
	token := strings.TrimPrefix(strings.TrimSpace(raw), "PVEAPIToken=")
	id, secret, ok := strings.Cut(token, "=")
	if !ok || secret == "" {
		return "", badConnection(form)
	}
	user, tokenID, ok := strings.Cut(id, "!")
	if !ok || tokenID == "" || !strings.Contains(user, "@") {
		return "", badConnection(form)
	}
	for _, r := range token {
		if r <= ' ' || r >= 0x7f {
			return "", badConnection(form)
		}
	}
	return token, nil
}

// normalizeFingerprint returns a SHA-256 fingerprint as lowercase hex, from
// the AA:BB:... form Proxmox VE and openssl print.
func normalizeFingerprint(raw string) (string, error) {
	fp := strings.ToLower(strings.ReplaceAll(raw, ":", ""))
	if b, err := hex.DecodeString(fp); err != nil || len(b) != sha256.Size {
		return "", badConnection("the fingerprint must be a SHA-256 fingerprint, as AA:BB:...")
	}
	return fp, nil
}

func caPool(caPEM string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest := []byte(caPEM)
	n := 0
	for {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, badConnection("the CA certificate cannot be parsed")
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, badConnection("the CA file holds no PEM certificate")
	}
	return pool, nil
}

// tlsConfig verifies the server as c says. Verification is never off: a
// pinned fingerprint replaces the chain check with a stricter one.
func tlsConfig(c Connection) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch c.tlsMode() {
	case TLSCA:
		pool, err := caPool(c.CAPEM)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	case TLSFingerprint:
		want, err := hex.DecodeString(c.Fingerprint)
		if err != nil {
			return nil, badConnection("the fingerprint is not hex")
		}
		// VerifyConnection below takes over from the chain check, on every
		// connection including resumed ones.
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the server sent no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if !bytes.Equal(got[:], want) {
				return errors.New("the server's certificate does not match the pinned fingerprint")
			}
			return nil
		}
	}
	return cfg, nil
}

// client calls one server's API.
type client struct {
	base  string
	token string
	hc    *http.Client
}

func newClient(c Connection) (*client, error) {
	tlsCfg, err := tlsConfig(c)
	if err != nil {
		return nil, err
	}
	return &client{
		base:  c.URL + "/api2/json",
		token: c.Token,
		hc: &http.Client{
			Timeout: requestTimeout,
			// A redirect could carry the token somewhere else.
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

// statusError is an API answer other than success.
type statusError struct {
	code    int
	message string
}

func (e *statusError) Error() string {
	switch e.code {
	case http.StatusUnauthorized:
		return "the server refused the API token"
	case http.StatusForbidden:
		return "the API token lacks a privilege for this: " + e.message
	case statusNodeUnreachable:
		return "the node is unreachable"
	}
	if e.message != "" {
		return fmt.Sprintf("the server answered %d: %s", e.code, e.message)
	}
	return fmt.Sprintf("the server answered %d", e.code)
}

// do calls the API and decodes the data of its answer into out, if not nil.
func (c *client) do(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "PVEAPIToken="+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return requestError(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return requestError(err)
	}
	if resp.StatusCode != http.StatusOK {
		return &statusError{code: resp.StatusCode, message: c.serverMessage(resp, body)}
	}
	if out == nil {
		return nil
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return errors.New("the server's answer is not valid JSON")
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return errors.New("the server's answer has an unexpected form")
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

// serverMessage is what the server said went wrong: in the body, or failing
// that the status line. It is cut short and can never carry the token.
func (c *client) serverMessage(resp *http.Response, body []byte) string {
	var env struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &env) // an error page has no message
	msg := strings.TrimSpace(env.Message)
	if msg == "" {
		msg = strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)))
	}
	msg = strings.ReplaceAll(msg, c.token, "[token]")
	if _, secret, ok := strings.Cut(c.token, "="); ok {
		msg = strings.ReplaceAll(msg, secret, "[token]")
	}
	if len(msg) > maxMessage {
		msg = msg[:maxMessage] + "…"
	}
	return msg
}

// num reads a number the API may send as a number, a quoted number or a
// boolean: its schema and its wire format do not always agree (a "boolean" is
// 0 or 1 on the wire).
type num float64

// UnmarshalJSON implements json.Unmarshaler. What is no number counts as 0.
func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	switch s {
	case "true":
		*n = 1
		return nil
	case "false", "null", "":
		*n = 0
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		*n = 0
		return nil //nolint:nilerr // one odd field must not fail the whole read
	}
	*n = num(f)
	return nil
}

// resource is one entry of GET /cluster/resources.
type resource struct {
	Type       string `json:"type"`
	Node       string `json:"node"`
	Status     string `json:"status"`
	Name       string `json:"name"`
	VMID       num    `json:"vmid"`
	Template   num    `json:"template"`
	CPU        num    `json:"cpu"`
	MaxCPU     num    `json:"maxcpu"`
	Mem        num    `json:"mem"`
	MaxMem     num    `json:"maxmem"`
	Disk       num    `json:"disk"`
	MaxDisk    num    `json:"maxdisk"`
	Uptime     num    `json:"uptime"`
	Storage    string `json:"storage"`
	PluginType string `json:"plugintype"`
	Content    string `json:"content"`
	Shared     num    `json:"shared"`
}

// resources reads the nodes, guests and storage of the whole cluster in one
// request, which still answers when a node is down.
func (c *client) resources(ctx context.Context) ([]resource, error) {
	var out []resource
	if err := c.do(ctx, http.MethodGet, "/cluster/resources", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// guestAction asks the node g runs on to start, stop or reboot it, and
// returns the ID of the task the server queued.
func (c *client) guestAction(ctx context.Context, g Guest, verb string) (string, error) {
	path := "/nodes/" + url.PathEscape(g.Node) + "/" + g.Kind + "/" + strconv.Itoa(g.VMID) + "/status/" + verb
	var upid string
	if err := c.do(ctx, http.MethodPost, path, &upid); err != nil {
		return "", err
	}
	return upid, nil
}
