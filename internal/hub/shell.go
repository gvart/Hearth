// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const (
	// DefaultShellIdleTimeout ends a terminal session nobody typed in for
	// this long.
	DefaultShellIdleTimeout = 15 * time.Minute
	// DefaultShellMaxDuration ends any terminal session this long after it
	// opened.
	DefaultShellMaxDuration = 4 * time.Hour
	// maxShellFrame bounds a browser message: a paste or a resize.
	maxShellFrame = 64 << 10
	// shellWriteTimeout bounds a write to the browser.
	shellWriteTimeout = 30 * time.Second
	// shellOpenTimeout bounds the wait for the agent to start the shell.
	shellOpenTimeout = 30 * time.Second
)

func (a *api) shellRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/devices/{id}/shell", a.auth(a.deviceShell))
}

// ShellMessageJSON is a text message of the terminal WebSocket, from the
// hub: pending (held for approval), started, exit or error. Output and
// input are binary messages; the browser's text messages are resizes:
// {"type": "resize", "rows": 24, "cols": 80}.
type ShellMessageJSON struct {
	Type string `json:"type"`
	// Shell is the program the agent started (started).
	Shell string `json:"shell,omitempty"`
	// IdleTimeout and MaxDuration are the session's limits, in seconds (started).
	IdleTimeout int `json:"idle_timeout,omitempty"`
	MaxDuration int `json:"max_duration,omitempty"`
	// Approval and Expires name the approval the session waits for (pending).
	Approval string     `json:"approval,omitempty"`
	Expires  *time.Time `json:"expires,omitempty"`
	// ExitCode is the shell's exit status, -1 if it was killed (exit).
	ExitCode *int32 `json:"exit_code,omitempty"`
	// Reason says why the session ended (exit) or failed (error).
	Reason string `json:"reason,omitempty"`
	// Code classifies an error: forbidden, not_connected or failed.
	Code string `json:"code,omitempty"`
	// Rows and Cols are a resize (from the browser).
	Rows uint32 `json:"rows,omitempty"`
	Cols uint32 `json:"cols,omitempty"`
}

// shellFrame is one WebSocket message, text or binary.
type shellFrame struct {
	binary bool
	data   []byte
}

var shellCodec = websocket.Codec{
	Marshal: func(v any) ([]byte, byte, error) {
		f, ok := v.(shellFrame)
		if !ok {
			return nil, 0, errors.New("not a shell frame")
		}
		if f.binary {
			return f.data, websocket.BinaryFrame, nil
		}
		return f.data, websocket.TextFrame, nil
	},
	Unmarshal: func(msg []byte, payloadType byte, v any) error {
		f, ok := v.(*shellFrame)
		if !ok {
			return errors.New("not a shell frame")
		}
		f.binary, f.data = payloadType == websocket.BinaryFrame, msg
		return nil
	},
}

// deviceShell upgrades to a WebSocket that bridges a terminal in the
// browser to a shell on the device. Policy decides on it (device.shell,
// dangerous, web sessions only) and audits its start and its end; the
// device's agent opens it only if its ceiling allows shells.
func (a *api) deviceShell(w http.ResponseWriter, r *http.Request) {
	if a.agents == nil {
		writeError(w, http.StatusNotFound, "not_found", "this hub serves no terminals")
		return
	}
	// The session cookie is SameSite=Strict, but another port of the same
	// host is the same site: only the hub's own pages may open a terminal.
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "cross-origin terminal request")
		return
	}
	dev, err := a.store.Devices().Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such device")
		return
	}
	if err != nil {
		a.log.ErrorContext(r.Context(), "get device", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot get device")
		return
	}
	rows, cols := queryUint(r, "rows", 24), queryUint(r, "cols", 80)
	websocket.Server{
		Handshake: func(*websocket.Config, *http.Request) error { return nil }, // origin checked above
		Handler:   func(ws *websocket.Conn) { a.serveShell(r, ws, dev, rows, cols) },
	}.ServeHTTP(w, r)
}

// sameOrigin reports whether the request's Origin is the hub itself.
func sameOrigin(r *http.Request) bool {
	u, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || u.Host == "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return u.Scheme == scheme && u.Host == r.Host
}

func queryUint(r *http.Request, name string, def uint32) uint32 {
	n, err := strconv.ParseUint(r.URL.Query().Get(name), 10, 16)
	if err != nil || n == 0 {
		return def
	}
	return uint32(n)
}

// serveShell runs one terminal session on ws until the shell exits, the
// browser goes away, the session idles or outlasts its maximum, the admin
// session that opened it ends, or the request's context ends.
func (a *api) serveShell(r *http.Request, ws *websocket.Conn, dev store.Device, rows, cols uint32) {
	ctx, actor := r.Context(), remoteHost(r)
	defer func() { _ = ws.Close() }()
	ws.MaxPayloadBytes = maxShellFrame
	send := func(f shellFrame) error {
		_ = ws.SetWriteDeadline(time.Now().Add(shellWriteTimeout))
		return shellCodec.Send(ws, f)
	}
	sendJSON := func(m ShellMessageJSON) {
		b, _ := json.Marshal(m)
		_ = send(shellFrame{data: b})
	}

	detail := map[string]any{"device": dev.Name}
	req := policy.Request{
		ActorKind: policy.ActorWeb, ActorID: actor, Action: policy.DeviceShell, Target: dev.ID, Detail: detail,
		Precheck: func(ctx context.Context) error { return a.agents.CheckShell(ctx, dev.ID) },
		OnHold: func(id string, expires time.Time) {
			sendJSON(ShellMessageJSON{Type: "pending", Approval: id, Expires: &expires})
		},
	}
	var sh *Shell
	err := a.policy.Do(ctx, req, func(ctx context.Context) error {
		// The browser is not read until the shell runs: an agent that never
		// answers must not hold the session forever.
		ctx, cancel := context.WithTimeoutCause(ctx, shellOpenTimeout, errors.New("the agent did not start the shell in time"))
		defer cancel()
		s, err := a.agents.OpenShell(ctx, dev.ID, rows, cols)
		if err != nil {
			return err
		}
		sh = s
		// Recorded in the audit entry Do writes once this returns, and in
		// the end's, which pairs with it by session.
		detail["shell"] = s.Path()
		detail["session"] = s.id
		return nil
	})
	if err != nil {
		code := "failed"
		switch {
		case errors.Is(err, policy.ErrDenied):
			code = "forbidden"
		case errors.Is(err, ErrAgentNotConnected):
			code = "not_connected"
		}
		if ctx.Err() == nil {
			a.log.InfoContext(ctx, "terminal refused", "device_id", dev.ID, "remote", actor, "err", err)
		}
		sendJSON(ShellMessageJSON{Type: "error", Code: code, Reason: err.Error()})
		return
	}

	idle, maxDur := a.shellIdle, a.shellMax
	opened := a.now()
	a.log.InfoContext(ctx, "terminal opened", "device_id", dev.ID, "remote", actor, "shell", sh.Path())
	sendJSON(ShellMessageJSON{
		Type: "started", Shell: sh.Path(),
		IdleTimeout: int(idle / time.Second), MaxDuration: int(maxDur / time.Second),
	})

	// reason is why the hub ended the session, set once.
	var reason atomic.Pointer[string]
	end := func(why string) {
		reason.CompareAndSwap(nil, &why)
		sh.Close()
	}
	var lastInput atomic.Int64
	lastInput.Store(time.Now().UnixNano())
	done := make(chan struct{})
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() { // the browser: input and resizes, until it goes away
		for {
			var f shellFrame
			if err := shellCodec.Receive(ws, &f); err != nil {
				end("terminal closed")
				return
			}
			lastInput.Store(time.Now().UnixNano())
			if f.binary {
				_ = sh.Write(f.data)
				continue
			}
			var m ShellMessageJSON
			if json.Unmarshal(f.data, &m) == nil && m.Type == "resize" && m.Rows > 0 && m.Cols > 0 {
				_ = sh.Resize(m.Rows, m.Cols)
			}
		}
	})
	wg.Go(func() { // the limits
		tick := time.NewTicker(min(idle/4, time.Second*10))
		defer tick.Stop()
		deadline := time.NewTimer(maxDur)
		defer deadline.Stop()
		for {
			select {
			case <-done:
				return
			case <-deadline.C:
				end("maximum session duration reached")
				return
			case <-tick.C:
				if time.Since(time.Unix(0, lastInput.Load())) >= idle {
					end("idle timeout")
					return
				}
				// A failed lookup says nothing about the session: only its
				// absence or expiry ends the terminal.
				if _, err := a.checkSession(r); errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrSessionExpired) {
					end("signed out")
					return
				}
			}
		}
	})

	// The shell's output, until the session ends.
	readCtx := ctx
	for {
		out, err := sh.Read(readCtx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil { // ctx: the hub is stopping
			end("hub stopping")
			// The end follows, or Close gives up waiting for it.
			readCtx = context.WithoutCancel(ctx)
			continue
		}
		if err := send(shellFrame{binary: true, data: out}); err != nil {
			end("terminal closed")
		}
	}
	close(done)
	ex := sh.Exit()
	why := "shell exited"
	if p := reason.Load(); p != nil {
		why = *p
	} else if ex.GetError() != "" {
		why = ex.GetError()
	}
	code := ex.GetExitCode()
	sendJSON(ShellMessageJSON{Type: "exit", ExitCode: &code, Reason: why})
	_ = ws.Close() // ends the browser reader

	took := a.now().Sub(opened).Round(time.Second)
	a.log.InfoContext(ctx, "terminal closed", "device_id", dev.ID, "remote", actor, "duration", took, "reason", why)
	if err := a.policy.RecordEnd(context.WithoutCancel(ctx), req,
		fmt.Sprintf("ended: %s, exit %d after %s", why, code, took),
		map[string]any{"event": "end", "duration_s": int(took / time.Second), "exit_code": code, "reason": why},
	); err != nil {
		a.log.ErrorContext(ctx, "audit terminal end", "err", err)
	}
}
