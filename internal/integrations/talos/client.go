// SPDX-License-Identifier: AGPL-3.0-only

// Package talos reads Talos Linux nodes through the Talos API (apid) with
// the client certificate of a talosconfig: their version, services and
// health, memory, load and boot time. It only reads.
//
// The API is gRPC. The client speaks it with connect-go, which the hub
// already uses, and decodes the few response fields it needs by hand
// (protowire), so the Talos machinery module and grpc-go stay out of the
// binary. It can call only the read methods listed in readMethods: nothing
// in this package can upgrade, reboot or otherwise change a node, even with
// an os:admin talosconfig.
package talos

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"
)

// Read methods of machine.MachineService, the only ones the client calls.
// Each takes google.protobuf.Empty.
const (
	methodVersion     = "Version"
	methodHostname    = "Hostname"
	methodServiceList = "ServiceList"
	methodMemory      = "Memory"
	methodLoadAvg     = "LoadAvg"
	methodSystemStat  = "SystemStat"
)

// readMethods is the allowlist of the client; call refuses any other.
var readMethods = map[string]bool{
	methodVersion: true, methodHostname: true, methodServiceList: true,
	methodMemory: true, methodLoadAvg: true, methodSystemStat: true,
}

const (
	// callTimeout bounds one call to the API.
	callTimeout = 10 * time.Second
	// maxResponse caps a response the hub reads.
	maxResponse = 8 << 20
)

// errNotRead is returned for a method outside readMethods.
var errNotRead = errors.New("not a read method of the Talos API")

// Client reads Talos nodes through the first endpoint of a talosconfig
// context that answers.
type Client struct {
	cfg  Config
	http *http.Client
}

// New returns a client for cfg. It connects on the first read.
func New(cfg Config) *Client {
	tr := &http.Transport{
		TLSClientConfig:     cfg.TLS,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: callTimeout,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     2 * time.Minute,
	}
	return &Client{cfg: cfg, http: &http.Client{Transport: tr}}
}

// Target names what the client reads, for the audit log: the context and
// its first endpoint.
func (c *Client) Target() string {
	return c.cfg.Context + "@" + c.cfg.Endpoints[0]
}

// Nodes are the nodes the client reads.
func (c *Client) Nodes() []string { return c.cfg.Nodes }

// empty is google.protobuf.Empty: it encodes to no bytes.
type empty struct{}

// raw is a response kept as its protobuf bytes, decoded by the caller.
type raw struct{ b []byte }

// codec is the "proto" codec for empty requests and raw responses.
type codec struct{}

func (codec) Name() string { return "proto" }

func (codec) Marshal(v any) ([]byte, error) {
	if _, ok := v.(*empty); !ok {
		return nil, fmt.Errorf("talos codec: cannot marshal %T", v)
	}
	return nil, nil
}

func (codec) Unmarshal(b []byte, v any) error {
	r, ok := v.(*raw)
	if !ok {
		return fmt.Errorf("talos codec: cannot unmarshal into %T", v)
	}
	r.b = append(r.b[:0], b...)
	return nil
}

// call calls a read method on nodes through the first endpoint that
// answers, and returns the response bytes. The nodes go in the "nodes"
// metadata, so apid proxies the call to each and tags every reply with the
// node it came from.
func (c *Client) call(ctx context.Context, method string, nodes []string) ([]byte, error) {
	if !readMethods[method] {
		return nil, fmt.Errorf("%s: %w", method, errNotRead)
	}
	var errs []error
	for _, ep := range c.cfg.Endpoints {
		b, err := c.callAt(ctx, ep, method, nodes)
		if err == nil {
			return b, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		errs = append(errs, fmt.Errorf("%s: %w", ep, err))
	}
	return nil, fmt.Errorf("talos %s: %w", method, errors.Join(errs...))
}

func (c *Client) callAt(ctx context.Context, endpoint, method string, nodes []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	cl := connect.NewClient[empty, raw](c.http, "https://"+endpoint+"/machine.MachineService/"+method,
		connect.WithGRPC(), connect.WithCodec(codec{}), connect.WithReadMaxBytes(maxResponse))
	req := connect.NewRequest(&empty{})
	for _, n := range nodes {
		req.Header().Add("nodes", n)
	}
	res, err := cl.CallUnary(ctx, req)
	if err != nil {
		return nil, err
	}
	return res.Msg.b, nil
}
