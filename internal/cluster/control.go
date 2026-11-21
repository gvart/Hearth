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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// ControlSocket is the file name of a hub's local control socket. CLI
// commands on the hub host use it to read the member's status and to send
// writes through the hub's replicator instead of writing the local database
// behind the cluster's back. See ControlSocketPath for where it lives.
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

type caStatusReply struct {
	Status CAStatus   `json:"status"`
	Error  *wireError `json:"error,omitempty"`
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
	Kind    string `json:"kind,omitempty"`
	Message string `json:"message"`
	// Owner and What name a master-owned row's owner (kind not_owner).
	Owner string `json:"owner,omitempty"`
	What  string `json:"what,omitempty"`
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
	"rotation_owner":       ErrRotationOwner,
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
	var no *store.NotOwnerError
	if errors.As(err, &no) {
		return &wireError{Kind: "not_owner", Message: err.Error(), Owner: no.Owner, What: no.What}
	}
	for kind, target := range wireKinds {
		if errors.Is(err, target) {
			return &wireError{Kind: kind, Message: err.Error()}
		}
	}
	return &wireError{Message: err.Error()}
}

func (e *wireError) toError() error {
	if e.Kind == "not_owner" {
		return &store.NotOwnerError{What: e.What, Owner: e.Owner}
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

// ControlClient talks to a running hub through its control socket. It is a
// store.Applier, so a CLI command can open the store for reads and send its
// writes through the hub's replicator.
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
