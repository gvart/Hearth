// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"encoding/json"
	"fmt"
)

// The owner's own record of the master-owned rows it created (#382).
//
// A master-owned row (an enrollment or join token, an approval, an approval
// link) is sharded: a storage member is one of its replicas, and could write
// one naming any master as its owner, or change one a master wrote. The
// owner keeps the command that created each row it owns, outside the
// replicated store, and takes what it grants (roles, labels, the approval a
// link is for) from that record, never from a replica.

// OwnedCreate returns the key ("table/key", as OwnedUse) of the master-owned
// row cmd creates, and its owner, if cmd creates one.
func OwnedCreate(cmd Command) (key, owner string, ok bool) {
	switch c := cmd.(type) {
	case CreateToken:
		return "tokens/" + keyString(c.Hash), c.Owner, true
	case CreateJoinToken:
		return "join_tokens/" + keyString(c.Hash), c.Owner, true
	case CreateApproval:
		return "approvals/" + c.ID, c.Owner, true
	case CreateApprovalLink:
		return "approval_links/" + keyString(c.Hash), c.Owner, true
	}
	return "", "", false
}

// OwnedResult checks use, a use of a master-owned row, against created, the
// command that created that row on this master, and returns res, the use's
// result, with what the row grants taken from created. A use past the
// row's expiry fails with ErrTokenExpired.
func OwnedResult(created, use Command, res Result) (Result, error) {
	now := int64(0)
	switch u := use.(type) {
	case ConsumeToken:
		now = u.Now
	case ConsumeJoinToken:
		now = u.Now
	case UseApprovalLink:
		now = u.Now
	}
	expired := func(at int64) error {
		if now != 0 && at <= now {
			return ErrTokenExpired
		}
		return nil
	}
	switch c := created.(type) {
	case CreateToken:
		if _, ok := use.(ConsumeToken); !ok {
			break
		}
		if err := expired(c.ExpiresAt); err != nil {
			return Result{}, err
		}
		var labels map[string]string
		if err := json.Unmarshal([]byte(c.Labels), &labels); err != nil {
			return Result{}, fmt.Errorf("decode labels: %w", err)
		}
		res.Labels, res.Name, res.HubRoles = labels, c.Name, c.HubRoles
		return res, nil
	case CreateJoinToken:
		if _, ok := use.(ConsumeJoinToken); !ok {
			break
		}
		if err := expired(c.ExpiresAt); err != nil {
			return Result{}, err
		}
		res.Roles, res.DeviceID = c.Roles, c.DeviceID
		return res, nil
	case CreateApprovalLink:
		if _, ok := use.(UseApprovalLink); !ok {
			break
		}
		if err := expired(c.ExpiresAt); err != nil {
			return Result{}, err
		}
		res.ApprovalID = c.ApprovalID
		return res, nil
	case CreateApproval:
		if _, ok := use.(DecideApproval); !ok {
			break
		}
		return res, nil
	}
	return Result{}, fmt.Errorf("%s does not use the row %s created", use.Op(), created.Op())
}

// OwnerDecisions is implemented by an Applier that keeps the owner's record
// of the approvals it decided (an AP cluster's): Approvals.OwnerDecision asks
// it.
type OwnerDecisions interface {
	// OwnerDecision returns the decision this member, the approval's owner,
	// made on approval id, "" if none.
	OwnerDecision(ctx context.Context, id string) (string, error)
}

// OwnerDecision returns the decision this hub made on approval id, and
// whether it keeps such a record: in an AP cluster only the owner decides,
// and the approval's replicas, which may include a storage member, cannot
// approve it for the owner (#382). A hub that keeps none (one alone) holds
// every row itself.
func (r Approvals) OwnerDecision(ctx context.Context, id string) (status string, checked bool, err error) {
	d, ok := r.s.applier.(OwnerDecisions)
	if !ok {
		return "", false, nil
	}
	status, err = d.OwnerDecision(ctx, id)
	return status, true, err
}
