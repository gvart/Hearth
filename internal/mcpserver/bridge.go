// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
)

// maxMessage bounds one JSON-RPC message, either way.
const maxMessage = 16 << 20

// Bridge relays MCP messages between a stdio client, which writes one
// JSON-RPC message per line to in and reads them from out, and the hub's
// streamable HTTP endpoint, as the MCP token token. It runs the client's
// requests concurrently and returns once in ends and every request is
// answered, or ctx is done. A request the hub cannot answer gets a JSON-RPC
// error, so the client never waits for nothing.
func Bridge(ctx context.Context, endpoint, token string, hc *http.Client, in io.Reader, out io.Writer, log *slog.Logger) error {
	b := &bridge{endpoint: endpoint, token: token, hc: hc, out: out, log: log}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), maxMessage)
	var wg sync.WaitGroup
	defer wg.Wait()
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		msg := bytes.Clone(line)
		wg.Go(func() { b.relay(ctx, msg) })
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	return nil
}

type bridge struct {
	endpoint string
	token    string
	hc       *http.Client
	log      *slog.Logger

	outMu sync.Mutex
	out   io.Writer

	mu sync.Mutex
	// protocol is the protocol version initialize settled on; later
	// requests name it, as streamable HTTP requires.
	protocol string
	// sessionID is the hub's session id, if it hands one out.
	sessionID string
}

// message is the part of a JSON-RPC message the bridge reads.
type message struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Result *struct {
		ProtocolVersion string `json:"protocolVersion"`
	} `json:"result,omitempty"`
}

// relay posts one message to the hub and writes every message of its
// answer to out.
func (b *bridge) relay(ctx context.Context, msg []byte) {
	var m message
	if err := json.Unmarshal(msg, &m); err != nil {
		b.fail(nil, "not a JSON-RPC message: "+err.Error())
		return
	}
	if err := b.post(ctx, msg, m.Method == "initialize"); err != nil {
		b.log.WarnContext(ctx, "relay to hub", "method", m.Method, "err", err)
		b.fail(m.ID, err.Error())
	}
}

func (b *bridge) post(ctx context.Context, msg []byte, initialize bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, bytes.NewReader(msg))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+b.token)
	b.mu.Lock()
	if b.protocol != "" {
		req.Header.Set("Mcp-Protocol-Version", b.protocol)
	}
	if b.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", b.sessionID)
	}
	b.mu.Unlock()
	res, err := b.hc.Do(req)
	if err != nil {
		return fmt.Errorf("hub unreachable: %w", err)
	}
	defer res.Body.Close()
	if id := res.Header.Get("Mcp-Session-Id"); id != "" {
		b.mu.Lock()
		b.sessionID = id
		b.mu.Unlock()
	}
	if res.StatusCode == http.StatusAccepted {
		return nil // a notification or a response
	}
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<10))
		if res.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("the hub refused the MCP token (HEARTH_MCP_TOKEN): %s", strings.TrimSpace(string(body)))
		}
		return fmt.Errorf("hub answered %s: %s", res.Status, strings.TrimSpace(string(body)))
	}
	emit := func(data []byte) error {
		var buf bytes.Buffer
		if err := json.Compact(&buf, data); err != nil {
			return fmt.Errorf("hub sent a bad message: %w", err)
		}
		if initialize {
			var m message
			if json.Unmarshal(buf.Bytes(), &m) == nil && m.Result != nil && m.Result.ProtocolVersion != "" {
				b.mu.Lock()
				b.protocol = m.Result.ProtocolVersion
				b.mu.Unlock()
			}
		}
		return b.write(buf.Bytes())
	}
	mt, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	switch mt {
	case "application/json":
		body, err := io.ReadAll(io.LimitReader(res.Body, maxMessage))
		if err != nil {
			return fmt.Errorf("read hub answer: %w", err)
		}
		return emit(body)
	case "text/event-stream":
		return readEvents(res.Body, emit)
	}
	return fmt.Errorf("hub answered with content type %q", mt)
}

// readEvents calls emit with the data of each server-sent event in r.
func readEvents(r io.Reader, emit func([]byte) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxMessage)
	var data []byte
	flush := func() error {
		if len(data) == 0 {
			return nil
		}
		d := data
		data = nil
		return emit(d)
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if err := flush(); err != nil {
				return err
			}
		case strings.HasPrefix(line, "data:"):
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")...)
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("read hub events: %w", err)
	}
	return flush()
}

// fail answers the request id, if it is one, with a JSON-RPC error.
func (b *bridge) fail(id json.RawMessage, msg string) {
	if len(id) == 0 || string(id) == "null" {
		return // a notification: nobody waits for an answer
	}
	out, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32603, "message": "hearth: " + msg},
	})
	if err == nil {
		_ = b.write(out)
	}
}

func (b *bridge) write(msg []byte) error {
	b.outMu.Lock()
	defer b.outMu.Unlock()
	if _, err := b.out.Write(append(msg, '\n')); err != nil {
		return fmt.Errorf("write stdout: %w", err)
	}
	return nil
}
