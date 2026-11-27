// SPDX-License-Identifier: AGPL-3.0-only

// Package openwrt adopts OpenWrt routers through ubus over HTTP (uhttpd's
// /ubus JSON-RPC, with an rpcd session login): it reads the router's system
// info, its interfaces' traffic counters and its clients (DHCP leases and
// wireless associations), feeds the clients to network discovery, and
// restarts dnsmasq only through policy (openwrt.dnsmasq.restart, dangerous).
//
// The password and the session ID are sealed or held in memory only: they
// are never logged, put in an error or served by the API.
package openwrt

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
	"strings"
	"sync"
	"time"
)

const (
	// requestTimeout bounds one ubus request, from dial to the end of the body.
	requestTimeout = 10 * time.Second
	dialTimeout    = 5 * time.Second
	// maxBody caps a response the hub will read.
	maxBody = 4 << 20
	// nullSession is the session ID of an unauthenticated call: the login.
	nullSession = "00000000000000000000000000000000"
)

// ubus status codes (libubus), as the first element of a call's result.
const (
	statusOK               = 0
	statusMethodNotFound   = 3
	statusNotFound         = 4
	statusPermissionDenied = 6
)

// JSON-RPC errors of uhttpd's ubus handler.
const (
	rpcObjectNotFound = -32000
	rpcSessionMissing = -32001
	rpcAccessDenied   = -32002
)

var (
	// ErrBadLogin is returned when the router refuses the username or password.
	ErrBadLogin = errors.New("the router refused the username or password")
	// errDenied is a call the login's ACL does not allow.
	errDenied = errors.New("not allowed by the user's rpcd ACL")
	// errMissing is an object or method the router does not have: a package
	// that is not installed.
	errMissing = errors.New("not on this router")
	errBadJSON = errors.New("the router's answer is not valid JSON-RPC")
)

// client calls one router's ubus. It logs in on the first call, and again
// when the router no longer knows its session.
type client struct {
	endpoint string
	user     string
	pass     string
	hc       *http.Client

	mu  sync.Mutex
	sid string
	// denied are the object/method pairs this session was refused, even
	// after a fresh login: rpcd attaches ACLs at login, so asking again with
	// the same session changes nothing.
	denied map[string]bool
	nextID int
}

func newClient(c Connection) (*client, error) {
	tlsCfg, err := tlsConfig(c)
	if err != nil {
		return nil, err
	}
	return &client{
		endpoint: c.URL + "/ubus",
		user:     c.Username,
		pass:     c.Password,
		hc: &http.Client{
			Timeout: requestTimeout,
			// A redirect could carry the password somewhere else.
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

// rpcError is a JSON-RPC error of the ubus handler.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// statusError is a ubus call that answered a status other than OK.
type statusError int

func (e statusError) Error() string { return fmt.Sprintf("ubus status %d", int(e)) }

// rawCall makes one JSON-RPC call with session sid and returns the data of
// its result, or the JSON-RPC error or ubus status it failed with.
func (c *client) rawCall(ctx context.Context, sid, object, method string, args any) (json.RawMessage, error) {
	if args == nil {
		args = struct{}{}
	}
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.mu.Unlock()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "call", "params": []any{sid, object, method, args},
	})
	if err != nil {
		return nil, fmt.Errorf("encode ubus call: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("build ubus request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, requestError(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, requestError(err)
	}
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		if strings.HasPrefix(c.endpoint, "http://") {
			return nil, errors.New("the router redirects to https: use an https:// URL")
		}
		return nil, fmt.Errorf("the router answered %d, a redirect", resp.StatusCode)
	case resp.StatusCode == http.StatusNotFound:
		return nil, errors.New("the router has no /ubus: install uhttpd-mod-ubus (LuCI brings it)")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("the router answered %d", resp.StatusCode)
	}
	var env struct {
		Result []json.RawMessage `json:"result"`
		Error  *rpcError         `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, errBadJSON
	}
	if env.Error != nil {
		return nil, env.Error
	}
	if len(env.Result) == 0 {
		return nil, errBadJSON
	}
	var status int
	if err := json.Unmarshal(env.Result[0], &status); err != nil {
		return nil, errBadJSON
	}
	if status != statusOK {
		return nil, statusError(status)
	}
	if len(env.Result) < 2 {
		return json.RawMessage("{}"), nil
	}
	return env.Result[1], nil
}

func (e *rpcError) Error() string { return fmt.Sprintf("ubus error %d", e.Code) }

// requestError drops the URL an http.Client error starts with.
func requestError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// login opens a session and returns its ID.
func (c *client) login(ctx context.Context) (string, error) {
	data, err := c.rawCall(ctx, nullSession, "session", "login", map[string]any{"username": c.user, "password": c.pass})
	var se statusError
	switch {
	case errors.As(err, &se) && int(se) == statusPermissionDenied:
		return "", ErrBadLogin
	case err != nil:
		return "", fmt.Errorf("log in: %w", err)
	}
	var out struct {
		Session string `json:"ubus_rpc_session"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.Session == "" || len(out.Session) > 64 {
		return "", fmt.Errorf("log in: %w", errBadJSON)
	}
	return out.Session, nil
}

// session returns the current session, logging in if there is none.
func (c *client) session(ctx context.Context) (string, bool, error) {
	c.mu.Lock()
	sid := c.sid
	c.mu.Unlock()
	if sid != "" {
		return sid, false, nil
	}
	sid, err := c.login(ctx)
	if err != nil {
		return "", false, err
	}
	c.mu.Lock()
	c.sid, c.denied = sid, map[string]bool{}
	c.mu.Unlock()
	return sid, true, nil
}

// batch is a run of calls (one read, one action) that may log in again once
// between them.
type batch struct {
	c *client
	// relogged says the batch already logged in, or logged in again.
	relogged bool
}

func (c *client) batch() *batch { return &batch{c: c} }

// call calls object.method with args and decodes its data into out, if not
// nil. The first call of a batch refused with access denied logs in again,
// as the router answers so for an expired session too; after a login in the
// batch, a refusal means the session's ACL lacks the call, and the session
// remembers it. So a login whose ACL lacks several calls costs one login,
// not one per call and per read.
func (b *batch) call(ctx context.Context, object, method string, args, out any) error {
	c := b.c
	key := object + "." + method
	sid, fresh, err := c.session(ctx)
	if err != nil {
		return err
	}
	b.relogged = b.relogged || fresh
	c.mu.Lock()
	known := c.sid == sid && c.denied[key]
	c.mu.Unlock()
	if known {
		return fmt.Errorf("%s: %w", key, errDenied)
	}
	data, err := c.rawCall(ctx, sid, object, method, args)
	if isAccessDenied(err) && !b.relogged {
		b.relogged = true
		c.mu.Lock()
		if c.sid == sid {
			c.sid = ""
		}
		c.mu.Unlock()
		if sid, _, err = c.session(ctx); err != nil {
			return err
		}
		data, err = c.rawCall(ctx, sid, object, method, args)
	}
	if isAccessDenied(err) {
		c.mu.Lock()
		if c.sid == sid {
			c.denied[key] = true
		}
		c.mu.Unlock()
		return fmt.Errorf("%s: %w", key, errDenied)
	}
	if err != nil {
		var re *rpcError
		var se statusError
		if (errors.As(err, &re) && re.Code == rpcObjectNotFound) ||
			(errors.As(err, &se) && (int(se) == statusNotFound || int(se) == statusMethodNotFound)) {
			return fmt.Errorf("%s: %w", key, errMissing)
		}
		return fmt.Errorf("%s: %w", key, err)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: the router's answer has an unexpected form", key)
	}
	return nil
}

// isAccessDenied reports whether err is the router's refusal of a session:
// unknown, expired, or lacking the call in its ACL.
func isAccessDenied(err error) bool {
	var re *rpcError
	if errors.As(err, &re) {
		return re.Code == rpcAccessDenied || re.Code == rpcSessionMissing
	}
	var se statusError
	return errors.As(err, &se) && int(se) == statusPermissionDenied
}
