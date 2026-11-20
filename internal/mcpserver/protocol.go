// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// The part of MCP the hub speaks: streamable HTTP without sessions, where
// each POST carries one JSON-RPC message and a request is answered with one
// application/json response; initialize, ping, tools/list and tools/call.
// It is written out rather than taken from an MCP SDK: the SDK's packages
// and their dependencies would grow the one hearth binary by about 2 MB and
// every idle agent by about 1 MB of RSS, near the agent's 25 MB budget.

// protocolVersions are the MCP revisions the hub speaks, newest first.
var protocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

// maxRequest bounds one request body.
const maxRequest = 1 << 20

// JSON-RPC error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// endpoint serves MCP to requests that requireToken admitted.
type endpoint struct{ cfg Config }

func (e *endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// No sessions: there is no stream to open with GET nor one to end
		// with DELETE.
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequest))
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPC(w, rpcResponse{ID: json.RawMessage("null"), Error: &rpcError{codeParse, "parse error: " + err.Error()}})
		return
	}
	if req.JSONRPC != "2.0" {
		writeRPC(w, rpcResponse{ID: orNull(req.ID), Error: &rpcError{codeInvalidRequest, `jsonrpc must be "2.0"`}})
		return
	}
	if len(req.ID) == 0 || string(req.ID) == "null" {
		// A notification, or a response to a request the hub never sends.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	tok, _ := r.Context().Value(tokenKey{}).(store.MCPToken)
	s := &session{cfg: e.cfg, tok: tok}
	result, rerr := s.handle(r, req)
	writeRPC(w, rpcResponse{ID: req.ID, Result: result, Error: rerr})
}

// sameOrigin refuses a browser's cross-origin request, as MCP asks of
// servers to defeat DNS rebinding. Clients that are not browsers send no
// Origin.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func orNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

func writeRPC(w http.ResponseWriter, res rpcResponse) {
	res.JSONRPC = "2.0"
	if res.Error == nil && res.Result == nil {
		res.Result = struct{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// handle answers one request.
func (s *session) handle(r *http.Request, req rpcRequest) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := protocolVersions[0]
		if slices.Contains(protocolVersions, p.ProtocolVersion) {
			version = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "hearth", "version": s.cfg.Version},
			"instructions": "Hearth is the control plane of this homelab. Every tool call is decided by the hub's " +
				"policy and audited. Dangerous actions may be held until an operator approves them " +
				"(`hearth approval list`, then `hearth approval approve <id>`); the call then waits for the decision.",
		}, nil
	case "ping":
		return struct{}{}, nil
	case "tools/list":
		tools := []map[string]any{}
		for _, t := range s.offered() {
			tools = append(tools, map[string]any{
				"name": t.name, "description": t.description, "inputSchema": t.schema,
				"annotations": annotations(t.class),
			})
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{codeInvalidParams, "params must be {name, arguments}"}
		}
		tools := s.offered()
		i := slices.IndexFunc(tools, func(t tool) bool { return t.name == p.Name })
		if i < 0 {
			return nil, &rpcError{codeInvalidParams, fmt.Sprintf("unknown tool %q", p.Name)}
		}
		out, err := tools[i].call(r.Context(), p.Arguments)
		return toolResult(out, err), nil
	}
	return nil, &rpcError{codeMethodNotFound, "method not found: " + req.Method}
}

func annotations(class policy.Class) map[string]any {
	a := map[string]any{"readOnlyHint": class == policy.Read}
	if class != policy.Read {
		a["destructiveHint"] = class == policy.Dangerous
	}
	return a
}

// toolResult is a tool's answer: out as text, JSON unless it is a string,
// or err as a tool error, which the client shows the model.
func toolResult(out any, err error) map[string]any {
	text, isErr := "", err != nil
	switch v := out.(type) {
	case nil:
	case string:
		text = v
	default:
		b, merr := json.MarshalIndent(v, "", "  ")
		if merr != nil {
			text, isErr = "encode result: "+merr.Error(), true
		} else {
			text = string(b)
		}
	}
	if err != nil {
		text = err.Error()
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isErr}
}

// inputSchema is the JSON Schema of a tool's arguments, the struct t: one
// property per field, named by its json tag and described by its
// jsonschema tag; fields without omitempty are required.
func inputSchema(t reflect.Type) map[string]any {
	props, required := map[string]any{}, []string{}
	for f := range t.Fields() {
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		p := typeSchema(f.Type)
		if d := f.Tag.Get("jsonschema"); d != "" {
			p["description"] = d
		}
		props[name] = p
		if !strings.Contains(opts, "omitempty") {
			required = append(required, name)
		}
	}
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

func typeSchema(t reflect.Type) map[string]any {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": typeSchema(t.Elem())}
	}
	return map[string]any{} // any value; json.Unmarshal checks it
}
