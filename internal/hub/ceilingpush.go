// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// The capability ceiling the hub manages for a device (#346) reaches its
// agent in a CeilingConfig: on every connect, an empty one too, so a saved
// ceiling the store no longer has goes; on a change made on the hub holding
// the stream at once; and from every heartbeat, which compares the stored
// ceiling with the one the stream last got, so a change made on another
// master or by the CLI arrives within a heartbeat interval.

// minCeilingConfigMinor is the first agent protocol minor version that takes
// a CeilingConfig.
const minCeilingConfigMinor = 10

// ceilingReader reads the ceilings the hub sets. store.DeviceCeilings is one.
type ceilingReader interface {
	Get(ctx context.Context, device string) (store.DeviceCeiling, error)
}

// storedCeiling is the ceiling set for device, or an empty one if none was.
func storedCeiling(ctx context.Context, r ceilingReader, device string) (*agentv1.Ceiling, error) {
	dc, err := r.Get(ctx, device)
	if errors.Is(err, store.ErrNotFound) {
		return &agentv1.Ceiling{}, nil
	}
	if err != nil {
		return nil, err
	}
	c := &agentv1.Ceiling{}
	if err := protojson.Unmarshal(dc.Ceiling, c); err != nil {
		return nil, fmt.Errorf("decode the ceiling of device %s: %w", device, err)
	}
	return c, nil
}

// syncCeiling sends sess the ceiling stored for its device when it differs
// from the one it last got. A failed read or send is logged: the next
// heartbeat tries again.
func (s *AgentStream) syncCeiling(ctx context.Context, log *slog.Logger, sess *agentSession) {
	if s.ceilings == nil || sess.minor < minCeilingConfigMinor {
		return
	}
	c, err := storedCeiling(ctx, s.ceilings, sess.device)
	if err != nil {
		log.WarnContext(ctx, "read the device's capability ceiling", "err", err)
		return
	}
	if err := sess.pushCeiling(c); err != nil {
		log.WarnContext(ctx, "send the device's capability ceiling", "err", err)
	}
}

// pushCeiling sends c in a CeilingConfig unless the stream's agent got it
// last.
func (s *agentSession) pushCeiling(c *agentv1.Ceiling) error {
	s.ceilingMu.Lock()
	defer s.ceilingMu.Unlock()
	if s.sentCeiling != nil && proto.Equal(s.sentCeiling, c) {
		return nil
	}
	msg := &agentv1.HubMessage{Payload: &agentv1.HubMessage_CeilingConfig{CeilingConfig: &agentv1.CeilingConfig{Ceiling: c}}}
	if err := s.sendMsg(msg); err != nil {
		return err
	}
	s.sentCeiling = proto.CloneOf(c)
	return nil
}

// PushCeiling sends c, the ceiling just set for device, to its agent if it
// streams to this hub and takes one. Agents streaming elsewhere get it from
// their next heartbeat there.
func (a *Agents) PushCeiling(device string, c *agentv1.Ceiling) error {
	a.mu.Lock()
	sess := a.sessions[device]
	a.mu.Unlock()
	if sess == nil || sess.minor < minCeilingConfigMinor {
		return nil
	}
	return sess.pushCeiling(c)
}
