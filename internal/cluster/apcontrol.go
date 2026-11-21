// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gvart/hearth/internal/policy"
)

// IsAP reports whether dataDir belongs to a member of an AP cluster.
func IsAP(dataDir string) bool {
	b, err := os.ReadFile(filepath.Join(dataDir, RaftDir, apModeFile))
	return err == nil && strings.TrimSpace(string(b)) == "ap"
}

// RoleChangeRequest is a promotion, demotion or removal the CLI on a
// master's host asks the running hub for (`hearth cluster promote|demote|
// remove`). The hub decides it with its own policy engine, so an isolated
// master refuses it as it refuses the UI.
type RoleChangeRequest struct {
	// Op is promote, demote or remove.
	Op     string `json:"op"`
	Member string `json:"member"`
	Role   string `json:"role,omitempty"`
	DryRun bool   `json:"dry_run,omitempty"`
	// Actor names the admin, as the audit log does (user@host).
	Actor string `json:"actor"`
}

// RoleChangeFunc runs a RoleChangeRequest through policy: the hub's master
// layer sets it while this member is a master.
type RoleChangeFunc func(ctx context.Context, req RoleChangeRequest) (any, error)

type roleChangeReply struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *wireError      `json:"error,omitempty"`
}

// errDeniedKind is the wire kind of a policy denial.
const errDeniedKind = "denied"

// SetRoleChanges sets what runs the CLI's role changes; nil while this
// member is no master.
func (n *APNode) SetRoleChanges(f RoleChangeFunc) {
	if f == nil {
		n.changeFn.Store(nil)
		return
	}
	n.changeFn.Store(&f)
}

// serveRoleChange answers POST /v1/change on the control socket.
func (n *APNode) serveRoleChange(w http.ResponseWriter, r *http.Request) {
	var req RoleChangeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var reply roleChangeReply
	f := n.changeFn.Load()
	if f == nil {
		reply.Error = &wireError{Kind: "not_master", Message: ErrNotMasterHere.Error() + " (run the command on a master's host)"}
		writeJSON(w, reply)
		return
	}
	out, err := (*f)(r.Context(), req)
	switch {
	case err == nil:
		reply.Result, _ = json.Marshal(out)
	case errors.Is(err, policy.ErrDenied):
		reply.Error = &wireError{Kind: errDeniedKind, Message: err.Error()}
	default:
		reply.Error = &wireError{Kind: RoleErrorKind(err), Message: err.Error()}
	}
	writeJSON(w, reply)
}

// ChangeRoles asks the running hub to promote, demote or remove a member
// (RoleChangeRequest) and decodes its result into out. A refusal keeps its
// kind: errors.Is matches policy.ErrDenied and the role change errors.
func (c *ControlClient) ChangeRoles(ctx context.Context, req RoleChangeRequest, out any) error {
	// A change held for approval waits for it: no client timeout.
	var reply roleChangeReply
	if err := c.postWith(ctx, &http.Client{Transport: c.http.Transport}, "/v1/change", req, &reply); err != nil {
		return err
	}
	if reply.Error != nil {
		if reply.Error.Kind == errDeniedKind {
			return &kindError{msg: reply.Error.Message, target: policy.ErrDenied}
		}
		if target, ok := roleKinds[reply.Error.Kind]; ok {
			return &kindError{msg: reply.Error.Message, target: target}
		}
		return errors.New(reply.Error.Message)
	}
	if out != nil && len(reply.Result) > 0 {
		if err := json.Unmarshal(reply.Result, out); err != nil {
			return fmt.Errorf("hub control socket: decode result: %w", err)
		}
	}
	return nil
}
