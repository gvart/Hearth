// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// Forwarding between the masters of an AP cluster (docs/design/ap-cluster.md
// §6). An agent streams to one master, which records the route
// (store.DeviceRoutes). A request on another master that needs the stream
// (an exec, a probe, a Docker call, a scan, from the API, MCP, an automation
// or a runbook) is forwarded to that master over the masters' mutual-TLS
// link and run there on the stream. The policy decision and its audit entry
// stay on the master that received the request; the master holding the
// stream checks the agent's ceiling again, as for its own requests. A log
// stream or a terminal is proxied to that master as the HTTP request it is,
// and authenticated and decided there.

// Masters is the other masters of an AP cluster, as the hub reaches them.
type Masters interface {
	// Self is this master's id.
	Self() string
	// Live reports whether master id is alive.
	Live(id string) bool
	// AgentURLOf is master id's agent-facing URL, or "".
	AgentURLOf(ctx context.Context, id string) string
	// Client sends requests to http://<master id>/... over the link.
	Client() *http.Client
	// OwnerOf is the master owning key (a runbook run, an automation) on
	// the ring of live masters.
	OwnerOf(key string) string
}

// forwardTimeout bounds a forwarded call without a deadline of its own.
const forwardTimeout = 2 * time.Minute

// routeRefresh is how often the master holding a stream writes its route
// again, so a route lost to a race (an older master's write winning) heals.
const routeRefresh = time.Minute

// forwardedKey marks a request that came from another master: it is never
// forwarded again.
type forwardedKey struct{}

func forwarded(ctx context.Context) bool { return ctx.Value(forwardedKey{}) != nil }

// ErrStreamElsewhere is a request for a device whose agent streams to a
// master this one cannot reach.
var ErrStreamElsewhere = errors.New("the device's agent streams to another hub, which cannot be reached; " +
	"the agent is reconnecting to one that can")

// SetMasters makes a forward the requests for devices whose agent streams to
// another master of an AP cluster (routes says which).
func (a *Agents) SetMasters(m Masters, routes store.DeviceRoutes) {
	a.masters, a.routes = m, routes
}

// Local reports whether device id's agent streams to this hub.
func (a *Agents) Local(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessions[id] != nil
}

// holder returns the live master, other than this one, that device id's
// agent streams to, or "" if there is none.
func (a *Agents) holder(ctx context.Context, id string) string {
	if a.masters == nil || forwarded(ctx) {
		return ""
	}
	route, err := a.routes.Get(ctx, id)
	if err != nil || route.Master == a.masters.Self() || !a.masters.Live(route.Master) {
		return ""
	}
	return route.Master
}

// forwardTo returns the master to forward a request for device to, when
// err, the local lookup's error, says its agent has no stream here.
func (a *Agents) forwardTo(ctx context.Context, device string, err error) (master, id string, ok bool) {
	if a.masters == nil || forwarded(ctx) || !errors.Is(err, ErrAgentNotConnected) {
		return "", "", false
	}
	id, rerr := a.resolve(ctx, device)
	if rerr != nil {
		return "", "", false
	}
	if m := a.holder(ctx, id); m != "" {
		return m, id, true
	}
	return "", "", false
}

// agentCall is a request forwarded to the master holding a stream.
type agentCall struct {
	Device    string          `json:"device"`
	Req       json.RawMessage `json:"req,omitempty"`
	TimeoutMS int64           `json:"timeout_ms,omitempty"`
	Subnets   []string        `json:"subnets,omitempty"`
	// CheckOnly asks only whether the request would be sent.
	CheckOnly bool `json:"check_only,omitempty"`
}

// agentReply is its answer.
type agentReply struct {
	Result   json.RawMessage `json:"result,omitempty"`
	DeviceID string          `json:"device_id,omitempty"`
	Kind     string          `json:"kind,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// The errors a forwarded call carries back, by kind, most specific first:
// an error beyond the ceiling is also a denial.
var forwardKinds = []struct {
	kind   string
	target error
}{
	{"beyond_ceiling", policy.ErrBeyondCeiling},
	{"denied", policy.ErrDenied},
	{"not_connected", ErrAgentNotConnected},
	{"outcome_unknown", automation.ErrOutcomeUnknown},
	{"not_found", store.ErrNotFound},
}

func forwardKind(err error) string {
	for _, k := range forwardKinds {
		if errors.Is(err, k.target) {
			return k.kind
		}
	}
	return ""
}

func forwardTarget(kind string) error {
	for _, k := range forwardKinds {
		if k.kind == kind {
			return k.target
		}
	}
	return nil
}

// forwardError is an error a forwarded call returned: its message, matching
// its kind.
type forwardError struct {
	msg    string
	target error
}

func (e *forwardError) Error() string { return e.msg }
func (e *forwardError) Unwrap() error { return e.target }

// call sends a forwarded request to master and decodes its result into
// out, if any.
func (a *Agents) call(ctx context.Context, master, op string, in agentCall, req, out proto.Message) (string, error) {
	if req != nil {
		b, err := protojson.Marshal(req)
		if err != nil {
			return "", err
		}
		in.Req = b
	}
	body, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, forwardTimeout+time.Duration(in.TimeoutMS)*time.Millisecond)
		defer cancel()
	}
	// Once the request is written, the holder may have run it: a call lost
	// after that has an unknown outcome, as one lost on a local stream.
	var wrote atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { wrote.Store(true) },
	})
	lost := func(err error) error {
		if wrote.Load() && !in.CheckOnly {
			return fmt.Errorf("device %s: forwarded to hub %s: %w: %w", in.Device, master, automation.ErrOutcomeUnknown, err)
		}
		return fmt.Errorf("device %s: hub %s: %w (%w): %w", in.Device, master, ErrStreamElsewhere, ErrAgentNotConnected, err)
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+master+"/agents/"+op, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	hr.Header.Set("Content-Type", "application/json")
	resp, err := a.masters.Client().Do(hr)
	if err != nil {
		return "", lost(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var reply agentReply
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAgentMessage)).Decode(&reply); err != nil {
		return "", lost(err)
	}
	if reply.Error != "" {
		if target := forwardTarget(reply.Kind); target != nil {
			return "", &forwardError{msg: reply.Error, target: target}
		}
		return "", errors.New(reply.Error)
	}
	if out != nil {
		if err := protojson.Unmarshal(reply.Result, out); err != nil {
			return "", fmt.Errorf("device %s: forwarded to hub %s: %w", in.Device, master, err)
		}
	}
	return reply.DeviceID, nil
}

// AgentsHandler serves the requests other masters forward to the agent
// streams of this one, under /agents/. The caller authenticated them as a
// live master (cluster.MasterLink); the decision was made on the master
// that received the request.
func AgentsHandler(a *Agents, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	handle := func(op string, fn func(ctx context.Context, in agentCall) (proto.Message, string, error)) {
		mux.HandleFunc("POST /agents/"+op, func(w http.ResponseWriter, r *http.Request) {
			var in agentCall
			if err := json.NewDecoder(io.LimitReader(r.Body, maxAgentMessage)).Decode(&in); err != nil {
				writeJSON(w, http.StatusBadRequest, agentReply{Error: "bad request"})
				return
			}
			ctx := context.WithValue(r.Context(), forwardedKey{}, true)
			res, id, err := fn(ctx, in)
			if err != nil {
				writeJSON(w, http.StatusOK, agentReply{Error: err.Error(), Kind: forwardKind(err)})
				return
			}
			reply := agentReply{DeviceID: id}
			if res != nil {
				b, err := protojson.Marshal(res)
				if err != nil {
					log.WarnContext(ctx, "encode a forwarded agent result", "op", op, "err", err)
					writeJSON(w, http.StatusOK, agentReply{Error: "cannot encode the result"})
					return
				}
				reply.Result = b
			}
			writeJSON(w, http.StatusOK, reply)
		})
	}
	handle("exec", func(ctx context.Context, in agentCall) (proto.Message, string, error) {
		req := &agentv1.ExecRequest{}
		if err := protojson.Unmarshal(in.Req, req); err != nil {
			return nil, "", err
		}
		if in.CheckOnly {
			return nil, "", a.Check(ctx, in.Device, req)
		}
		res, err := a.Exec(ctx, in.Device, req)
		return res, "", err
	})
	handle("probe", func(ctx context.Context, in agentCall) (proto.Message, string, error) {
		if in.CheckOnly {
			return nil, "", a.CheckProbe(ctx, in.Device)
		}
		req := &agentv1.ProbeRequest{}
		if err := protojson.Unmarshal(in.Req, req); err != nil {
			return nil, "", err
		}
		res, err := a.Probe(ctx, in.Device, req)
		return res, "", err
	})
	handle("docker", func(ctx context.Context, in agentCall) (proto.Message, string, error) {
		req := &agentv1.DockerRequest{}
		if err := protojson.Unmarshal(in.Req, req); err != nil {
			return nil, "", err
		}
		if in.CheckOnly {
			return nil, "", a.CheckDocker(ctx, in.Device, req)
		}
		res, err := a.Docker(ctx, in.Device, req, time.Duration(in.TimeoutMS)*time.Millisecond)
		return res, "", err
	})
	handle("scan", func(ctx context.Context, in agentCall) (proto.Message, string, error) {
		subnets, err := parsePrefixes(in.Subnets)
		if err != nil {
			return nil, "", err
		}
		if in.CheckOnly {
			return nil, "", a.CheckScan(ctx, in.Device, subnets)
		}
		id, res, err := a.Scan(ctx, in.Device, subnets, time.Duration(in.TimeoutMS)*time.Millisecond)
		return res, id, err
	})
	return mux
}

func parsePrefixes(ss []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

// remoteHeader carries the client's address of a request proxied from
// another master, for the audit log; it is believed only on the masters'
// link.
const remoteHeader = "X-Hearth-Client-Addr"

// ProxiedHandler serves on this master the device stream requests (logs,
// terminal) other masters proxy to it: web, the hub's own UI and API. Their
// client authenticates there, by its session, and policy decides there, as
// for a request made here.
func ProxiedHandler(web http.Handler) http.Handler {
	mux := http.NewServeMux()
	serve := func(w http.ResponseWriter, r *http.Request) {
		if addr := r.Header.Get(remoteHeader); addr != "" {
			r.RemoteAddr = addr
		}
		r = r.WithContext(context.WithValue(r.Context(), forwardedKey{}, true))
		web.ServeHTTP(w, r)
	}
	mux.HandleFunc("GET /api/v1/devices/{id}/logs", serve)
	mux.HandleFunc("GET /api/v1/devices/{id}/shell", serve)
	return mux
}

// proxyStream serves next here when the device's agent streams to this hub
// or to no live master, and otherwise proxies the request to the master
// holding the stream.
func (a *api) proxyStream(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ag := a.agents
		if ag == nil || ag.masters == nil || forwarded(r.Context()) {
			next(w, r)
			return
		}
		id, err := ag.resolve(r.Context(), r.PathValue("id"))
		if err != nil || ag.Local(id) {
			next(w, r)
			return
		}
		master := ag.holder(r.Context(), id)
		if master == "" {
			next(w, r)
			return
		}
		target := &url.URL{Scheme: "http", Host: master}
		rp := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.Host = pr.In.Host // the terminal checks its Origin against it
				pr.Out.Header.Set(remoteHeader, pr.In.RemoteAddr)
			},
			Transport:     ag.masters.Client().Transport,
			FlushInterval: -1,
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				a.log.WarnContext(r.Context(), "proxy a device stream to its hub", "device_id", id, "hub", master, "err", err)
				writeError(w, http.StatusBadGateway, "agent_unreachable",
					"the device's agent streams to hub "+master+", which cannot be reached; it is reconnecting")
			},
		}
		rp.ServeHTTP(w, r)
	}
}
