// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
)

// ProtocolMajor is the agent protocol major version this hub speaks.
const ProtocolMajor = 1

// DefaultHeartbeatInterval is how often agents are told to send heartbeats.
const DefaultHeartbeatInterval = 10 * time.Second

// AgentStream implements agentv1connect.AgentServiceHandler.
type AgentStream struct {
	log               *slog.Logger
	heartbeatInterval time.Duration
	registry          *Registry
	now               func() time.Time
}

var _ agentv1connect.AgentServiceHandler = (*AgentStream)(nil)

// NewAgentStream returns an AgentService handler that reports to reg.
func NewAgentStream(log *slog.Logger, heartbeatInterval time.Duration, reg *Registry) *AgentStream {
	return &AgentStream{log: log, heartbeatInterval: heartbeatInterval, registry: reg, now: time.Now}
}

// Connect serves one agent stream: it requires a Hello first, checks the protocol
// version, replies Welcome, then consumes messages until the agent hangs up.
// The device is identified by its client certificate; the device_id in Hello is
// never trusted.
func (s *AgentStream) Connect(ctx context.Context, stream *connect.BidiStream[agentv1.AgentMessage, agentv1.HubMessage]) error {
	deviceID, ok := deviceIDFrom(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("no device identity"))
	}
	first, err := stream.Receive()
	if err != nil {
		return fmt.Errorf("receive hello: %w", err)
	}
	hello := first.GetHello()
	if hello == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("first message must be Hello"))
	}
	if got := hello.GetProtocolVersion().GetMajor(); got != ProtocolMajor {
		return connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("unsupported protocol major version %d: hub speaks %d", got, ProtocolMajor))
	}

	log := s.log.With("device_id", deviceID)
	if claimed := hello.GetDeviceId(); claimed != "" && claimed != deviceID {
		log.WarnContext(ctx, "ignoring device_id claimed in Hello", "claimed_device_id", claimed)
	}
	log.InfoContext(ctx, "agent connected", "hostname", hello.GetHostname(), "agent_version", hello.GetAgentVersion())
	if err := s.registry.ReportFacts(ctx, deviceID, hello); err != nil {
		log.ErrorContext(ctx, "record hello", "err", err)
		return connect.NewError(connect.CodeUnavailable, errors.New("cannot record device facts"))
	}

	welcome := &agentv1.HubMessage{Payload: &agentv1.HubMessage_Welcome{Welcome: &agentv1.Welcome{
		ServerTime:        timestamppb.New(s.now()),
		HeartbeatInterval: durationpb.New(s.heartbeatInterval),
	}}}
	if err := stream.Send(welcome); err != nil {
		return fmt.Errorf("send welcome to %s: %w", deviceID, err)
	}

	for {
		msg, err := stream.Receive()
		if errors.Is(err, io.EOF) {
			log.InfoContext(ctx, "agent disconnected")
			return nil
		}
		if err != nil {
			return fmt.Errorf("receive from %s: %w", deviceID, err)
		}
		// A failed registry update is logged, not fatal: the next heartbeat retries.
		switch p := msg.GetPayload().(type) {
		case *agentv1.AgentMessage_Heartbeat:
			log.DebugContext(ctx, "heartbeat")
			if err := s.registry.Heartbeat(ctx, deviceID); err != nil {
				log.WarnContext(ctx, "record heartbeat", "err", err)
			}
		case *agentv1.AgentMessage_Facts:
			log.DebugContext(ctx, "facts")
			if err := s.registry.ReportFacts(ctx, deviceID, p.Facts); err != nil {
				log.WarnContext(ctx, "record facts", "err", err)
			}
		case *agentv1.AgentMessage_Hello:
			return connect.NewError(connect.CodeInvalidArgument, errors.New("duplicate Hello"))
		default:
			// Metrics and exec results are handled by later tasks.
		}
	}
}
