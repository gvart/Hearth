// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// defaultLogTail is how many of the last lines a log stream starts with.
const defaultLogTail = 100

// logRoutes registers the device log stream, behind the admin session.
// Without Agents there is no route.
func (a *api) logRoutes(mux *http.ServeMux) {
	if a.agents == nil {
		return
	}
	mux.Handle("GET /api/v1/devices/{id}/logs", a.auth(a.proxyStream(a.deviceLogs)))
}

// LogLineJSON is one line of a log stream.
type LogLineJSON struct {
	// TS is when the line was written (RFC 3339), or null if the source
	// does not say.
	TS   *time.Time `json:"ts"`
	Text string     `json:"text"`
}

// LogLinesJSON is the data of a "lines" event of a log stream.
type LogLinesJSON struct {
	Lines []LogLineJSON `json:"lines"`
	// Skipped counts the lines dropped before these: the stream read too
	// slowly for the agent and the hub to keep them.
	Skipped uint64 `json:"skipped,omitempty"`
}

// LogEndJSON is the data of the "end" event that closes a log stream.
type LogEndJSON struct {
	// Error says why the stream ended; empty when the source just ended.
	Error string `json:"error,omitempty"`
}

// deviceLogs streams a log source of a device, given as
// ?source=manager:name, as server-sent events: "lines" events with
// LogLinesJSON, then an "end" event with LogEndJSON if the stream ends
// before the client goes away. Opening the stream is the policy action
// device.logs, audited once; the agent's ceiling must allow the source.
// When the client goes away the agent is told to stop reading.
func (a *api) deviceLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	manager, name, ok := strings.Cut(r.URL.Query().Get("source"), ":")
	if !ok || manager == "" || name == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "source must be manager:name, such as systemd:nginx.service")
		return
	}
	tail := uint64(defaultLogTail)
	if s := r.URL.Query().Get("tail"); s != "" {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "bad_request", "tail must be a positive number of lines")
			return
		}
		tail = n
	}
	device := r.PathValue("id")
	src := &agentv1.LogSource{Manager: manager, Name: name}
	var stream *LogStream
	err := a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.DeviceLogs, Target: device,
		Detail:   map[string]any{"source": manager + ":" + name, "tail": tail},
		Precheck: func(ctx context.Context) error { return a.agents.CheckLogs(ctx, device, src) },
	}, func(ctx context.Context) error {
		var err error
		stream, err = a.agents.Logs(ctx, device, src, uint32(tail)) //nolint:gosec // parsed as 32 bits
		return err
	})
	if stream != nil {
		defer stream.Close() // also when the audit entry could not be written
	}
	if err != nil {
		a.writeLogsError(w, r, err)
		return
	}

	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprint(w, ": subscribed\n\n"); err != nil || rc.Flush() != nil {
		return
	}

	// drain writes the messages waiting; done means the stream is over.
	drain := func() (done bool) {
		for m := stream.Take(); m != nil; m = stream.Take() {
			if len(m.GetLines()) > 0 || m.GetSkipped() > 0 {
				if writeSSE(w, "lines", logLinesJSON(m)) != nil {
					return true
				}
			}
			if m.GetEnd() {
				endLogs(w, rc, m.GetError())
				return true
			}
			if rc.Flush() != nil {
				return true
			}
		}
		return false
	}

	keepalive := time.NewTicker(a.keepalive)
	defer keepalive.Stop()
	for {
		var err error
		select {
		case <-ctx.Done():
			return
		case <-stream.Disconnected():
			if !drain() {
				endLogs(w, rc, "agent disconnected")
			}
			return
		case <-stream.Ready():
			if drain() {
				return
			}
			continue
		case <-keepalive.C:
			if _, err := a.checkSession(r); err != nil {
				return
			}
			_, err = fmt.Fprint(w, ": keepalive\n\n")
		}
		if err != nil || rc.Flush() != nil {
			return
		}
	}
}

// endLogs writes the "end" event of a log stream.
func endLogs(w http.ResponseWriter, rc *http.ResponseController, reason string) {
	if writeSSE(w, "end", LogEndJSON{Error: reason}) == nil {
		_ = rc.Flush()
	}
}

func logLinesJSON(m *agentv1.LogLines) LogLinesJSON {
	out := LogLinesJSON{Lines: make([]LogLineJSON, 0, len(m.GetLines())), Skipped: m.GetSkipped()}
	for _, l := range m.GetLines() {
		j := LogLineJSON{Text: l.GetText()}
		if l.GetTs() != nil {
			t := l.GetTs().AsTime()
			j.TS = &t
		}
		out.Lines = append(out.Lines, j)
	}
	return out
}

// writeSSE writes one server-sent event with v as its JSON data.
func writeSSE(w http.ResponseWriter, event string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	return err
}

// writeLogsError answers a log stream that could not be opened.
func (a *api) writeLogsError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, policy.ErrDenied):
		// The reason (beyond the ceiling, agent too old) is no secret, and
		// says what to change.
		writeError(w, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, ErrAgentNotConnected):
		writeError(w, http.StatusConflict, "agent_not_connected", "the device's agent is not connected to this hub")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such device")
	default:
		a.log.ErrorContext(r.Context(), "open log stream", "err", err)
		writeError(w, http.StatusBadGateway, "agent_error", err.Error())
	}
}
