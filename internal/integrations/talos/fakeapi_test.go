// SPDX-License-Identifier: AGPL-3.0-only

package talos

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protowire"
)

// fakeAPI is a Talos API (apid) serving the read methods over gRPC, like
// apid proxying to the nodes named in the "nodes" metadata. Any other
// method fails the test: the client must never call one.
type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server
	// down are nodes apid cannot reach: their replies carry only an error.
	down map[string]bool

	mu    sync.Mutex
	calls []string   // methods called, in order
	nodes [][]string // the "nodes" metadata of each call
}

// serverCodec is codec the other way round: it reads empty requests and
// writes raw responses.
type serverCodec struct{}

func (serverCodec) Name() string { return "proto" }

func (serverCodec) Marshal(v any) ([]byte, error) {
	r, ok := v.(*raw)
	if !ok {
		return nil, fmt.Errorf("cannot marshal %T", v)
	}
	return r.b, nil
}

func (serverCodec) Unmarshal(b []byte, v any) error {
	if _, ok := v.(*empty); !ok || len(b) != 0 {
		return fmt.Errorf("want an empty request, got %d bytes into %T", len(b), v)
	}
	return nil
}

func newFakeAPI(t *testing.T, down ...string) *fakeAPI {
	t.Helper()
	f := &fakeAPI{t: t, down: map[string]bool{}}
	for _, d := range down {
		f.down[d] = true
	}
	mux := http.NewServeMux()
	for m := range readMethods {
		path := "/machine.MachineService/" + m
		mux.Handle(path, connect.NewUnaryHandler(path, func(_ context.Context, req *connect.Request[empty]) (*connect.Response[raw], error) {
			nodes := req.Header().Values("nodes")
			f.mu.Lock()
			f.calls = append(f.calls, m)
			f.nodes = append(f.nodes, nodes)
			f.mu.Unlock()
			var b []byte
			for _, n := range nodes {
				b = protowire.AppendTag(b, fMessages, protowire.BytesType)
				b = protowire.AppendBytes(b, f.reply(m, n))
			}
			return connect.NewResponse(&raw{b: b}), nil
		}, connect.WithCodec(serverCodec{})))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("client called %s: not a read method", r.URL.Path)
		http.NotFound(w, r)
	})
	f.srv = httptest.NewUnstartedServer(mux)
	f.srv.EnableHTTP2 = true
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// endpoint is the fake's host:port.
func (f *fakeAPI) endpoint() string { return strings.TrimPrefix(f.srv.URL, "https://") }

// config is a client config reading nodes through the endpoints.
func (f *fakeAPI) config(endpoints []string, nodes ...string) Config {
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	return Config{
		Context: "lab", Endpoints: endpoints, Nodes: nodes,
		TLS: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}},
	}
}

func (f *fakeAPI) called() ([]string, [][]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...), append([][]string(nil), f.nodes...)
}

// Message builders.

func msg(fields ...[]byte) []byte {
	var b []byte
	for _, f := range fields {
		b = append(b, f...)
	}
	return b
}

func str(num protowire.Number, s string) []byte {
	b := protowire.AppendTag(nil, num, protowire.BytesType)
	return protowire.AppendString(b, s)
}

func sub(num protowire.Number, m []byte) []byte {
	b := protowire.AppendTag(nil, num, protowire.BytesType)
	return protowire.AppendBytes(b, m)
}

func varint(num protowire.Number, v uint64) []byte {
	b := protowire.AppendTag(nil, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

func double(num protowire.Number, v float64) []byte {
	b := protowire.AppendTag(nil, num, protowire.Fixed64Type)
	return protowire.AppendFixed64(b, math.Float64bits(v))
}

// reply is the reply of node n to method m, as apid proxies it: metadata
// first, with the node as hostname.
func (f *fakeAPI) reply(m, n string) []byte {
	if f.down[n] {
		return sub(fMetadata, msg(str(fMetaHostname, n), str(fMetaError, "dial tcp "+n+":50000: connect: no route to host")))
	}
	md := sub(fMetadata, str(fMetaHostname, n))
	// An unknown field of every kind, which the client must skip.
	unknown := msg(varint(99, 7), str(98, "x"), double(97, 1))
	switch m {
	case methodVersion:
		return msg(md, sub(fVersionInfo, msg(str(fVersionTag, "v1.12.7"), str(fVersionArch, "amd64"))),
			sub(fPlatformInfo, str(fPlatformName, "metal")), unknown)
	case methodHostname:
		return msg(md, str(fHostname, "talos-"+strings.ReplaceAll(n, ".", "-")))
	case methodServiceList:
		svc := func(id, state string, health []byte) []byte {
			s := msg(str(fServiceID, id), str(fServiceState, state))
			if health != nil {
				s = msg(s, sub(fServiceHealth, health))
			}
			return sub(fServices, s)
		}
		etcd := msg(varint(fHealthHealthy, 1))
		if n == "10.0.0.2" {
			etcd = msg(varint(fHealthHealthy, 0), str(fHealthMessage, "context deadline exceeded"))
		}
		return msg(md,
			svc("apid", "Running", msg(varint(fHealthHealthy, 1))),
			svc("dashboard", "Running", msg(varint(fHealthUnknown, 1))),
			svc("etcd", "Running", etcd),
			unknown)
	case methodMemory:
		return msg(md, sub(fMemInfo, msg(varint(fMemTotal, 16144744), varint(2, 2044628), varint(fMemAvailable, 11955304))))
	case methodLoadAvg:
		return msg(md, double(fLoad1, 1.5), double(fLoad5, 0.75), double(fLoad15, 0.25))
	case methodSystemStat:
		return msg(md, varint(fBootTime, 1778351076), sub(3, double(1, 12.5)))
	}
	f.t.Errorf("no reply for %s", m)
	return md
}
