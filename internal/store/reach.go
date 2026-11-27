// SPDX-License-Identifier: AGPL-3.0-only

package store

import "context"

// Reach is how many masters took a write that takes access away (a
// sign-out, a token or link revocation, a password reset) by the time it
// returned, of how many masters there are (#384). Such a write is never
// refused for want of a quorum: the masters that did not take it get it
// from hints when they are back, so a caller tells the user.
type Reach struct {
	Applied int `json:"applied"`
	Of      int `json:"of"`
}

// Partial reports whether some master has not taken the write yet.
func (r Reach) Partial() bool { return r.Applied < r.Of }

type reachKey struct{}

// WithReach returns ctx, with which a write that takes access away records
// its Reach in the returned one; it stays zero for a write that has none
// (outside a cluster, or another kind of write).
func WithReach(ctx context.Context) (context.Context, *Reach) {
	r := &Reach{}
	return context.WithValue(ctx, reachKey{}, r), r
}

// noteReach records res's Reach for the caller of WithReach on ctx.
func noteReach(ctx context.Context, res Result) {
	if res.Reach == nil {
		return
	}
	if r, ok := ctx.Value(reachKey{}).(*Reach); ok {
		*r = *res.Reach
	}
}

// TakesAccess reports whether cmd only takes access away from a master
// table's grants (#384): the writes no quorum refuses, whose Reach the
// caller is told.
func TakesAccess(cmd Command) bool {
	switch cmd.(type) {
	case DeleteSession, SetPasswordHash, RevokeMCPToken, RevokeDashboardToken, RevokePanelLink, DeletePanel:
		return true
	}
	return false
}
