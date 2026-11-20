// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Masters of an AP cluster (docs/design/ap-cluster.md §6): master-owned rows
// and the routes of agent streams.

// mastersSchema is the schema version whose migration (00029) added the
// owner columns and device_routes.
const mastersSchema = 29

// ErrNotOwner refuses to consume or decide a master-owned row (an
// enrollment or join token, an approval, an approval link) on a master that
// did not create it. Errors matching it are a *NotOwnerError naming the
// owner.
var ErrNotOwner = errors.New("owned by another master")

// NotOwnerError is ErrNotOwner with the owning master's node id.
type NotOwnerError struct {
	// What is what is owned: "token", "join token", "approval",
	// "approval link".
	What  string
	Owner string
}

func (e *NotOwnerError) Error() string {
	return fmt.Sprintf("this %s belongs to hub %s: only it can use or decide it", e.What, e.Owner)
}

// Is matches ErrNotOwner.
func (e *NotOwnerError) Is(target error) bool { return target == ErrNotOwner }

// OwnerOf returns the owning master named by an error matching ErrNotOwner,
// or "".
func OwnerOf(err error) string {
	var e *NotOwnerError
	if errors.As(err, &e) {
		return e.Owner
	}
	return ""
}

// checkOwner refuses master, a master consuming or deciding r, when r is
// owned by another master. A row without an owner (a single hub, a Raft
// cluster, a row from before mastersSchema) and a command without a master
// pass.
func checkOwner(r row, what, master string) error {
	if owner := r.str("owner"); owner != "" && master != "" && owner != master {
		return &NotOwnerError{What: what, Owner: owner}
	}
	return nil
}

// withOwner sets the owner column of r, a new master-owned row, when owner
// is set: below mastersSchema the column does not exist, and the commands
// that set it are gated on it.
func withOwner(r row, owner string) row {
	if owner != "" {
		r["owner"] = owner
	}
	return r
}

// ownedSchema is the schema a master-owned command needs: mastersSchema when
// it records or checks an owner, else base.
func ownedSchema(owner string, base int64) int64 {
	if owner != "" {
		return max(mastersSchema, base)
	}
	return base
}

// OwnedBy returns cmd for master id: a command creating a master-owned row
// records id as its owner, and one consuming or deciding such a row is
// refused with a *NotOwnerError unless id owns it. Fields already set are
// kept. Any other command is returned as it is. An AP cluster's applier
// calls it on every write, so the CLI's writes are owned by the hub whose
// control socket they reach.
func OwnedBy(cmd Command, id string) Command {
	switch c := cmd.(type) {
	case CreateToken:
		c.Owner = cmpOr(c.Owner, id)
		return c
	case CreateJoinToken:
		c.Owner = cmpOr(c.Owner, id)
		return c
	case CreateApproval:
		c.Owner = cmpOr(c.Owner, id)
		return c
	case CreateApprovalLink:
		c.Owner = cmpOr(c.Owner, id)
		return c
	case ConsumeToken:
		c.Master = cmpOr(c.Master, id)
		return c
	case ConsumeJoinToken:
		c.Master = cmpOr(c.Master, id)
		return c
	case DecideApproval:
		c.Master = cmpOr(c.Master, id)
		return c
	case UseApprovalLink:
		c.Master = cmpOr(c.Master, id)
		return c
	}
	return cmd
}

// OwnedUse reports whether cmd consumes or decides a master-owned row, and
// the key of that row ("table/key") the owner tracks its own uses by. An
// expiry of an approval is not one: any master may expire an approval past
// its expiry.
func OwnedUse(cmd Command) (string, bool) {
	switch c := cmd.(type) {
	case ConsumeToken:
		return "tokens/" + keyString(c.Hash), true
	case ConsumeJoinToken:
		return "join_tokens/" + keyString(c.Hash), true
	case DecideApproval:
		if c.Status == ApprovalExpired {
			return "", false
		}
		return "approvals/" + c.ID, true
	case UseApprovalLink:
		return "approval_links/" + keyString(c.Hash), true
	}
	return "", false
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// DeviceRoute is which master holds a device's agent stream, as that master
// last wrote it.
type DeviceRoute struct {
	DeviceID string
	Master   string
	At       time.Time
}

// DeviceRoutes is the repository of the device → master routes of an AP
// cluster: soft state, last-writer-wins, written with one replica.
type DeviceRoutes struct{ s *Store }

// DeviceRoutes returns the device routes repository.
func (s *Store) DeviceRoutes() DeviceRoutes { return DeviceRoutes{s: s} }

// Set records that master holds the stream of device at now.
func (r DeviceRoutes) Set(ctx context.Context, device, master string, now time.Time) error {
	if _, err := r.s.apply(ctx, SetDeviceRoute{DeviceID: device, Master: master, At: toMillis(now)}); err != nil {
		return fmt.Errorf("set route of device %s: %w", device, err)
	}
	return nil
}

// Get returns the route of device, or ErrNotFound.
func (r DeviceRoutes) Get(ctx context.Context, device string) (DeviceRoute, error) {
	var (
		master string
		at     int64
	)
	err := r.s.queryRowKey(ctx, device,
		`SELECT master, at FROM device_routes WHERE device_id = ? AND _deleted = 0`, device).Scan(&master, &at)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeviceRoute{}, fmt.Errorf("route of device %s: %w", device, ErrNotFound)
		}
		return DeviceRoute{}, fmt.Errorf("route of device %s: %w", device, err)
	}
	return DeviceRoute{DeviceID: device, Master: master, At: fromMillis(at)}, nil
}

// SetDeviceRoute records the master holding a device's agent stream.
type SetDeviceRoute struct {
	Stamp
	DeviceID string `json:"device_id"`
	Master   string `json:"master"`
	At       int64  `json:"at"`
}

// Op implements Command.
func (SetDeviceRoute) Op() string { return "set_device_route" }

func (SetDeviceRoute) minSchema() int64 { return mastersSchema }

func (c SetDeviceRoute) apply(ctx context.Context, w *writer) (Result, error) {
	return Result{}, w.put(ctx, "device_routes", row{"device_id": c.DeviceID, "master": c.Master, "at": c.At})
}

// Revokes reports whether cmd revokes a credential (a device, a hub
// certificate, an MCP or dashboard token, a panel link): an AP cluster tells
// every reachable member at once (docs/design/ap-cluster.md §5.4).
func Revokes(cmd Command) bool {
	switch cmd.(type) {
	case RevokeDevice, RevokeHubCerts, RevokeMCPToken, RevokeDashboardToken, RevokePanelLink:
		return true
	}
	return false
}

// Ref returns the reference of m's row: its table and primary key.
func (m Mutation) Ref() (RowRef, bool) {
	spec, ok := tables[m.Table]
	if !ok {
		return RowRef{}, false
	}
	key := make(Values, len(spec.pk))
	for i, c := range spec.pk {
		v, ok := m.Row[c]
		if !ok {
			return RowRef{}, false
		}
		key[i] = v
	}
	return RowRef{Table: m.Table, Key: key}, true
}
