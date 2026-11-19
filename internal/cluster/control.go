// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// ControlSocket is the file name of a clustered hub's local control socket.
// CLI commands on the hub host use it to read the node's status and to send
// writes through Raft instead of writing the local database behind the
// cluster's back. See ControlSocketPath for where it lives.
const ControlSocket = "hearth.sock"

// maxSocketPath stays under the smallest unix socket path limit (104 bytes
// on macOS and the BSDs, 108 on Linux).
const maxSocketPath = 100

// ControlSocketPath is where the hub using dataDir serves its control socket:
// inside the data dir (0700), or, when that path is too long for a unix
// socket, in a private (0700) directory under the user's temp dir named after
// a hash of the data dir.
func ControlSocketPath(dataDir string) string {
	p, _ := controlSocketPath(dataDir)
	return p
}

// controlSocketPath also reports whether the socket lives outside the data
// dir, in a directory of its own.
func controlSocketPath(dataDir string) (path string, ownDir bool) {
	if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs
	}
	p := filepath.Join(dataDir, ControlSocket)
	if len(p) <= maxSocketPath {
		return p, false
	}
	sum := sha256.Sum256([]byte(dataDir))
	return filepath.Join(os.TempDir(), "hearth-"+hex.EncodeToString(sum[:8]), ControlSocket), true
}

// privateSocketDir makes sure dir exists as a real directory with mode 0700,
// so only its owner can reach the socket inside it.
func privateSocketDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o700) {
		return fmt.Errorf("%s must be a directory with mode 0700", dir)
	}
	return nil
}

const maxCommandSize = 1 << 20

// ControlHandler serves the control API: GET /v1/status (with every hub's
// schema), POST /v1/apply (an encoded store command, proposed through node
// or forwarded to the leader), and the member operations /v1/remove,
// /v1/transfer-leadership and /v1/migrate, and /v1/ca/rotate, /v1/ca/finish, /v1/ca/abort and
// /v1/ca/status of a hub CA rotation.
func ControlHandler(node *Node, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := node.StatusWithSchemas(r.Context())
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
		res, err := node.ApplyOrForward(r.Context(), cmd)
		out := applyReply{Result: res}
		if err != nil {
			out.Error = toWireError(err)
			if out.Error.Kind == "" {
				log.WarnContext(r.Context(), "control apply failed", "op", cmd.Op(), "err", err)
			}
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("POST /v1/remove", func(w http.ResponseWriter, r *http.Request) {
		var req memberRequest
		if !readJSON(w, r, &req) {
			return
		}
		n, err := node.RemoveMember(r.Context(), req.NodeID)
		writeJSON(w, memberReply{Revoked: n, Error: wireErr(err)})
	})
	mux.HandleFunc("POST /v1/transfer-leadership", func(w http.ResponseWriter, r *http.Request) {
		var req memberRequest
		if !readJSON(w, r, &req) {
			return
		}
		err := node.TransferLeadership(r.Context(), req.NodeID)
		writeJSON(w, memberReply{Error: wireErr(err)})
	})
	mux.HandleFunc("POST /v1/migrate", func(w http.ResponseWriter, r *http.Request) {
		var req migrateRequest
		if !readJSON(w, r, &req) {
			return
		}
		from, err := node.MigrateSchema(r.Context(), req.To)
		writeJSON(w, migrateReply{From: from, Error: wireErr(err)})
	})
	mux.HandleFunc("POST /v1/ca/rotate", func(w http.ResponseWriter, r *http.Request) {
		var req RotateOptions
		if !readJSON(w, r, &req) {
			return
		}
		plan, err := node.RotateCA(r.Context(), req)
		writeJSON(w, rotateReply{Plan: plan, Error: wireErr(err)})
	})
	mux.HandleFunc("POST /v1/ca/finish", func(w http.ResponseWriter, r *http.Request) {
		var req FinishOptions
		if !readJSON(w, r, &req) {
			return
		}
		plan, err := node.FinishCA(r.Context(), req)
		writeJSON(w, finishReply{Plan: plan, Error: wireErr(err)})
	})
	mux.HandleFunc("POST /v1/ca/abort", func(w http.ResponseWriter, r *http.Request) {
		var req AbortOptions
		if !readJSON(w, r, &req) {
			return
		}
		plan, err := node.AbortCA(r.Context(), req)
		writeJSON(w, abortReply{Plan: plan, Error: wireErr(err)})
	})
	mux.HandleFunc("GET /v1/ca/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := node.CAStatus(r.Context())
		writeJSON(w, caStatusReply{Status: st, Error: wireErr(err)})
	})
	return mux
}

type rotateReply struct {
	Plan  RotatePlan `json:"plan"`
	Error *wireError `json:"error,omitempty"`
}

type finishReply struct {
	Plan  FinishPlan `json:"plan"`
	Error *wireError `json:"error,omitempty"`
}

type abortReply struct {
	Plan  AbortPlan  `json:"plan"`
	Error *wireError `json:"error,omitempty"`
}

type caStatusReply struct {
	Status CAStatus   `json:"status"`
	Error  *wireError `json:"error,omitempty"`
}

type migrateRequest struct {
	To int64 `json:"to"`
}

type migrateReply struct {
	From  int64      `json:"from"`
	Error *wireError `json:"error,omitempty"`
}

// memberRequest names a hub for /v1/remove and /v1/transfer-leadership.
type memberRequest struct {
	NodeID string `json:"node_id"`
}

type memberReply struct {
	Revoked int        `json:"revoked,omitempty"`
	Error   *wireError `json:"error,omitempty"`
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, maxCommandSize)).Decode(v); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func wireErr(err error) *wireError {
	if err == nil {
		return nil
	}
	return toWireError(err)
}

// ServeControl serves ControlHandler on the control socket of dataDir (see
// ControlSocketPath) until ctx is done. A stale socket file from an earlier
// run is replaced.
func ServeControl(ctx context.Context, dataDir string, node *Node, log *slog.Logger) error {
	path, ownDir := controlSocketPath(dataDir)
	if ownDir {
		if err := privateSocketDir(filepath.Dir(path)); err != nil {
			return fmt.Errorf("control socket: %w", err)
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("control socket: %w", err)
	}
	ln, err := listenPrivate(ctx, path)
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	defer func() { _ = os.Remove(path) }()
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

// listenPrivate listens on the unix socket path with mode 0600. Binding
// creates the socket file with the process umask (often 0755), so the socket
// is bound and chmodded inside a fresh 0700 directory next to path and only
// then renamed into place: path never names a socket with looser permissions.
// The temp name stays short so it fits the socket path limit whenever path
// does. The caller removes path once the listener is closed.
func listenPrivate(ctx context.Context, path string) (net.Listener, error) {
	tmpDir, err := os.MkdirTemp(filepath.Dir(path), "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	tmp := filepath.Join(tmpDir, "s")
	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", tmp)
	if err != nil {
		return nil, err
	}
	// The bound name is renamed away; closing must not unlink whatever
	// later takes its place.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
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
	"not_found":            store.ErrNotFound,
	"token_used":           store.ErrTokenUsed,
	"token_expired":        store.ErrTokenExpired,
	"unavailable":          store.ErrUnavailable,
	"closed":               store.ErrApprovalClosed,
	"run_conflict":         store.ErrRunbookRunConflict,
	"runs_unresolved":      store.ErrRunbookRunsUnresolved,
	"schema_old":           store.ErrSchemaTooOld,
	"ca_rotation_active":   store.ErrCARotationActive,
	"ca_rotation_conflict": store.ErrCARotationConflict,
	"unpinned_certs":       ErrUnpinnedCerts,
	"old_ca_holders":       ErrOldCAHolders,
	"no_rotation":          ErrNoRotation,
}

// kindError is a known store error received over the wire: it keeps the
// original message and matches its kind with errors.Is.
type kindError struct {
	msg    string
	target error
}

func (e *kindError) Error() string { return e.msg }
func (e *kindError) Unwrap() error { return e.target }

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
		return &kindError{msg: e.Message, target: target}
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
	path := ControlSocketPath(dataDir)
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

// RemoveMember removes hub id from the cluster through the hub's node (see
// Node.RemoveMember) and returns how many certificates were revoked.
func (c *ControlClient) RemoveMember(ctx context.Context, id string) (int, error) {
	var reply memberReply
	if err := c.post(ctx, "/v1/remove", memberRequest{NodeID: id}, &reply); err != nil {
		return 0, err
	}
	if reply.Error != nil {
		return 0, reply.Error.toError()
	}
	return reply.Revoked, nil
}

// TransferLeadership hands leadership to voter id, or to any voter when id is
// empty, through the hub's node (see Node.TransferLeadership).
func (c *ControlClient) TransferLeadership(ctx context.Context, id string) error {
	var reply memberReply
	if err := c.post(ctx, "/v1/transfer-leadership", memberRequest{NodeID: id}, &reply); err != nil {
		return err
	}
	if reply.Error != nil {
		return reply.Error.toError()
	}
	return nil
}

// MigrateSchema migrates the cluster's schema to version to through the
// hub's node (see Node.MigrateSchema) and returns the version it was at.
func (c *ControlClient) MigrateSchema(ctx context.Context, to int64) (int64, error) {
	var reply migrateReply
	if err := c.post(ctx, "/v1/migrate", migrateRequest{To: to}, &reply); err != nil {
		return 0, err
	}
	if reply.Error != nil {
		return 0, reply.Error.toError()
	}
	return reply.From, nil
}

// RotateCA starts a hub CA rotation through the hub's node (see
// Node.RotateCA). The plan comes back with a refusal too.
func (c *ControlClient) RotateCA(ctx context.Context, opts RotateOptions) (RotatePlan, error) {
	var reply rotateReply
	if err := c.post(ctx, "/v1/ca/rotate", opts, &reply); err != nil {
		return RotatePlan{}, err
	}
	if reply.Error != nil {
		return reply.Plan, reply.Error.toError()
	}
	return reply.Plan, nil
}

// FinishCA finishes the hub CA rotation through the hub's node (see
// Node.FinishCA), which waits for every hub, so for up to caFinishTimeout.
// The plan comes back with a refusal too.
func (c *ControlClient) FinishCA(ctx context.Context, opts FinishOptions) (FinishPlan, error) {
	ctx, cancel := context.WithTimeout(ctx, caFinishTimeout)
	defer cancel()
	long := &http.Client{Transport: c.http.Transport}
	var reply finishReply
	if err := c.postWith(ctx, long, "/v1/ca/finish", opts, &reply); err != nil {
		return FinishPlan{}, err
	}
	if reply.Error != nil {
		return reply.Plan, reply.Error.toError()
	}
	return reply.Plan, nil
}

// AbortCA gives up the hub CA rotation before its cutover through the hub's
// node (see Node.AbortCA). The plan comes back with a refusal too.
func (c *ControlClient) AbortCA(ctx context.Context, opts AbortOptions) (AbortPlan, error) {
	var reply abortReply
	if err := c.post(ctx, "/v1/ca/abort", opts, &reply); err != nil {
		return AbortPlan{}, err
	}
	if reply.Error != nil {
		return reply.Plan, reply.Error.toError()
	}
	return reply.Plan, nil
}

// CAStatus returns the hub CA rotation's status (see Node.CAStatus).
func (c *ControlClient) CAStatus(ctx context.Context) (CAStatus, error) {
	var reply caStatusReply
	if err := c.do(ctx, http.MethodGet, "/v1/ca/status", nil, &reply); err != nil {
		return CAStatus{}, err
	}
	if reply.Error != nil {
		return CAStatus{}, reply.Error.toError()
	}
	return reply.Status, nil
}

func (c *ControlClient) post(ctx context.Context, path string, body, out any) error {
	return c.postWith(ctx, c.http, path, body, out)
}

func (c *ControlClient) postWith(ctx context.Context, hc *http.Client, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return c.doWith(ctx, hc, http.MethodPost, path, b, out)
}

func (c *ControlClient) do(ctx context.Context, method, path string, body []byte, out any) error {
	return c.doWith(ctx, c.http, method, path, body, out)
}

func (c *ControlClient) doWith(ctx context.Context, hc *http.Client, method, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://hub"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
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
