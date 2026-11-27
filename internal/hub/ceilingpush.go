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
//
// Each config carries the stored row's version (its HLC). A session never
// sends one older than the last it sent, and the agent ignores one older
// than the one it applied, so a heartbeat that read the store before an
// admin lowered the ceiling cannot raise it again after the lowering.

// minCeilingConfigMinor is the first agent protocol minor version that takes
// a CeilingConfig.
const minCeilingConfigMinor = 10

// ceilingReader reads the ceilings the hub sets. store.DeviceCeilings is one.
type ceilingReader interface {
	Get(ctx context.Context, device string) (store.DeviceCeiling, error)
}

// storedCeiling is the ceiling set for device and its version, or an empty
// one of version 0 if none was.
func storedCeiling(ctx context.Context, r ceilingReader, device string) (*agentv1.CeilingConfig, error) {
	dc, err := r.Get(ctx, device)
	if errors.Is(err, store.ErrNotFound) {
		return &agentv1.CeilingConfig{Ceiling: &agentv1.Ceiling{}}, nil
	}
	if err != nil {
		return nil, err
	}
	c := &agentv1.Ceiling{}
	if err := protojson.Unmarshal(dc.Ceiling, c); err != nil {
		return nil, fmt.Errorf("decode the ceiling of device %s: %w", device, err)
	}
	return &agentv1.CeilingConfig{Ceiling: c, Version: dc.Version}, nil
}

// syncCeiling sends sess the ceiling stored for its device when it differs
// from the one it last got. A failed read or send is logged: the next
// heartbeat tries again.
func (s *AgentStream) syncCeiling(ctx context.Context, log *slog.Logger, sess *agentSession) {
	if s.ceilings == nil {
		return
	}
	if err := sess.syncCeiling(ctx, s.ceilings); err != nil {
		log.WarnContext(ctx, "send the device's capability ceiling", "err", err)
	}
}

// syncCeiling reads the stored ceiling and sends it, both under ceilingMu,
// so that no other push of the session runs between the read and the send.
func (s *agentSession) syncCeiling(ctx context.Context, r ceilingReader) error {
	if s.minor < minCeilingConfigMinor {
		return nil
	}
	s.ceilingMu.Lock()
	defer s.ceilingMu.Unlock()
	cfg, err := storedCeiling(ctx, r, s.device)
	if err != nil {
		return fmt.Errorf("read the device's capability ceiling: %w", err)
	}
	return s.pushCeilingLocked(cfg)
}

// pushCeilingLocked sends cfg unless the stream's agent got it, or a later
// one, already. The caller holds ceilingMu.
func (s *agentSession) pushCeilingLocked(cfg *agentv1.CeilingConfig) error {
	if s.sentCeiling != nil {
		if cfg.GetVersion() < s.sentCeiling.GetVersion() {
			return nil
		}
		if cfg.GetVersion() == s.sentCeiling.GetVersion() && proto.Equal(cfg.GetCeiling(), s.sentCeiling.GetCeiling()) {
			return nil
		}
	}
	msg := &agentv1.HubMessage{Payload: &agentv1.HubMessage_CeilingConfig{CeilingConfig: cfg}}
	if err := s.sendMsg(msg); err != nil {
		return err
	}
	s.sentCeiling = proto.CloneOf(cfg)
	return nil
}

// PushCeiling sends the ceiling just stored for device, read again from r
// with its version, to its agent if it streams to this hub and takes one.
// Agents streaming elsewhere get it from their next heartbeat there.
func (a *Agents) PushCeiling(ctx context.Context, r ceilingReader, device string) error {
	a.mu.Lock()
	sess := a.sessions[device]
	a.mu.Unlock()
	if sess == nil {
		return nil
	}
	return sess.syncCeiling(ctx, r)
}
