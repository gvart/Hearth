// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// ControlSocket is the file name, in the data dir, of a clustered hub's
// local control socket. CLI commands on the hub host use it to read the
// node's status and to send writes through Raft instead of writing the local
// database behind the cluster's back. Access is the data dir's: 0700.
const ControlSocket = "hearth.sock"

const maxCommandSize = 1 << 20

// ControlHandler serves the control API: GET /v1/status and POST /v1/apply
// (an encoded store command, proposed through node).
func ControlHandler(node *Node, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) {
		st, err := node.Status()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, st)
	})
	mux.HandleFunc("POST /v1/apply", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxCommandSize))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cmd, err := store.DecodeCommand(b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		res, err := node.Apply(r.Context(), cmd)
		out := applyReply{Result: res}
		if err != nil {
			out.Error = toWireError(err)
			if out.Error.Kind == "" {
				log.WarnContext(r.Context(), "control apply failed", "op", cmd.Op(), "err", err)
			}
		}
		writeJSON(w, out)
	})
	return mux
}

// ServeControl serves ControlHandler on the unix socket at path until ctx is
// done. A stale socket file from an earlier run is replaced.
func ServeControl(ctx context.Context, path string, node *Node, log *slog.Logger) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("control socket: %w", err)
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("control socket: %w", err)
	}
	srv := &http.Server{Handler: ControlHandler(node, log), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return fmt.Errorf("control socket: %w", err)
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("control socket: %w", err)
	}
	return nil
}

type applyReply struct {
	Result store.Result `json:"result"`
	Error  *wireError   `json:"error,omitempty"`
}

// wireError carries an Apply error across the control socket. Kind names the
// errors callers test for; anything else travels as its message.
type wireError struct {
	Kind       string `json:"kind,omitempty"`
	Message    string `json:"message"`
	LeaderID   string `json:"leader_id,omitempty"`
	LeaderAddr string `json:"leader_addr,omitempty"`
}

var wireKinds = map[string]error{
	"not_found":     store.ErrNotFound,
	"token_used":    store.ErrTokenUsed,
	"token_expired": store.ErrTokenExpired,
}

func toWireError(err error) *wireError {
	var nl *ErrNotLeader
	if errors.As(err, &nl) {
		return &wireError{Kind: "not_leader", Message: nl.Error(), LeaderID: nl.LeaderID, LeaderAddr: nl.LeaderAddr}
	}
	for kind, target := range wireKinds {
		if errors.Is(err, target) {
			return &wireError{Kind: kind, Message: err.Error()}
		}
	}
	return &wireError{Message: err.Error()}
}

func (e *wireError) toError() error {
	if e.Kind == "not_leader" {
		return &ErrNotLeader{LeaderID: e.LeaderID, LeaderAddr: e.LeaderAddr}
	}
	if target, ok := wireKinds[e.Kind]; ok {
		return target
	}
	return errors.New(e.Message)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ControlClient talks to a running clustered hub through its control socket.
// It is a store.Applier, so a CLI command can open the store for reads and
// send its writes through the hub's Raft node.
type ControlClient struct {
	path string
	http *http.Client
}

var _ store.Applier = (*ControlClient)(nil)

// DialControl returns a client for the hub using dataDir. It fails if the hub
// is not running.
func DialControl(dataDir string) (*ControlClient, error) {
	path := filepath.Join(dataDir, ControlSocket)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("this data dir belongs to a cluster member, but its hub is not running "+
			"(no control socket at %s): cluster writes go through the running hub", path)
	}
	return &ControlClient{path: path, http: &http.Client{
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}},
		Timeout: 30 * time.Second,
	}}, nil
}

// Status returns the node's view of the cluster.
func (c *ControlClient) Status(ctx context.Context) (Status, error) {
	var st Status
	err := c.do(ctx, http.MethodGet, "/v1/status", nil, &st)
	return st, err
}

// Apply implements store.Applier by proposing cmd through the hub's node.
func (c *ControlClient) Apply(ctx context.Context, cmd store.Command) (store.Result, error) {
	b, err := store.EncodeCommand(cmd)
	if err != nil {
		return store.Result{}, err
	}
	var reply applyReply
	if err := c.do(ctx, http.MethodPost, "/v1/apply", b, &reply); err != nil {
		return store.Result{}, err
	}
	if reply.Error != nil {
		return store.Result{}, reply.Error.toError()
	}
	return reply.Result, nil
}

func (c *ControlClient) do(ctx context.Context, method, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://hub"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("hub control socket %s: %w", c.path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("hub control socket: %s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("hub control socket: decode reply: %w", err)
	}
	return nil
}

// Close releases the client's connections.
func (c *ControlClient) Close() { c.http.CloseIdleConnections() }
