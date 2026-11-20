// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gvart/hearth/internal/metrics"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
	"github.com/gvart/hearth/internal/store"
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
	leadership        Leadership
	now               func() time.Time
	// certs, when set, re-checks each stream's client certificate on every
	// heartbeat, so a revocation (also one written by the CLI in another
	// process) ends a live stream within one heartbeat interval. authority
	// gates that judgement exactly as in requireClientCert.
	certs     certChecker
	authority func() error
	// pins, when set, records the fingerprint of a client certificate
	// issued before fingerprints were (see pinCert).
	pins certPinner
	// audit, when set, records a client certificate that is not the one
	// recorded for its serial.
	audit auditAppender
	// ca, rotations and renew, when set, renew agents during a hub CA
	// rotation (carotation.go), and end streams of certificates of a CA no
	// longer trusted.
	ca        *pki.CA
	rotations rotationReader
	renew     certRecorder
	// agents tracks open streams so exec requests can be sent over them.
	agents *Agents
	// metrics, when set, records the agents' MetricsBatches.
	metrics *metrics.Store
}

var _ agentv1connect.AgentServiceHandler = (*AgentStream)(nil)

// NewAgentStream returns an AgentService handler that reports to reg.
func NewAgentStream(log *slog.Logger, heartbeatInterval time.Duration, reg *Registry) *AgentStream {
	return &AgentStream{
		log: log, heartbeatInterval: heartbeatInterval, registry: reg, leadership: soloLeadership{}, now: time.Now,
		authority: func() error { return nil }, agents: NewAgents(reg.devices),
	}
}

// Connect serves one agent stream: it requires a Hello first, checks the protocol
// version, replies Welcome, then consumes messages until the agent hangs up.
// A hub that is not the cluster leader refuses the stream before reading it,
// with a NotLeader detail naming the leader.
// The device is identified by its client certificate; the device_id in Hello is
// never trusted.
func (s *AgentStream) Connect(ctx context.Context, stream *connect.BidiStream[agentv1.AgentMessage, agentv1.HubMessage]) error {
	deviceID, ok := deviceIDFrom(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("no device identity"))
	}
	if !s.leadership.IsLeader() {
		s.log.DebugContext(ctx, "agent refused: not the leader", "device_id", deviceID)
		return notLeaderError(s.leadership)
	}
	if s.registry.replicated {
		// A clustered leader serves agents only within a leadership term,
		// which starts once it has caught up with the cluster.
		if term, _ := ctx.Value(termKey{}).(context.Context); term == nil || term.Err() != nil {
			return connect.NewError(connect.CodeUnavailable, errors.New("this hub is taking over as the cluster leader; retry shortly"))
		}
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
	pinned := s.pinCert(ctx, log, deviceID)
	cert, bundle := s.renewal(ctx, log, deviceID)
	rotation, _ := s.rotationState(ctx)

	welcome := &agentv1.HubMessage{Payload: &agentv1.HubMessage_Welcome{Welcome: &agentv1.Welcome{
		ServerTime:        timestamppb.New(s.now()),
		HeartbeatInterval: durationpb.New(s.heartbeatInterval),
		Hubs:              s.leadership.AgentURLs(),
		Certificate:       cert,
		CaBundle:          bundle,
	}}}
	// Bounded as every send to an agent is (see agentSession.sendMsg).
	stalled := time.AfterFunc(s.agents.sendTimeout, streamAbort(ctx))
	err = stream.Send(welcome)
	stalled.Stop()
	if err != nil {
		return fmt.Errorf("send welcome to %s: %w", deviceID, err)
	}
	// From here on only Agents.Exec, Agents.Probe and Shells send on the stream.
	sess := s.agents.attach(deviceID, hello, stream.Send, streamAbort(ctx))
	defer s.agents.detach(deviceID, sess)

	for {
		msg, err := stream.Receive()
		if errors.Is(err, io.EOF) {
			log.InfoContext(ctx, "agent disconnected")
			return nil
		}
		if err != nil {
			if cause := context.Cause(ctx); errors.Is(cause, errStopping) {
				log.InfoContext(ctx, "agent stream ended: hub shutting down")
				return connect.NewError(connect.CodeUnavailable, cause)
			} else if errors.Is(cause, errSteppedDown) {
				log.InfoContext(ctx, "agent stream ended: no longer the cluster leader")
				return notLeaderError(s.leadership)
			} else if errors.Is(cause, errStreamStalled) {
				log.WarnContext(ctx, "agent stream torn down: the agent stopped reading it")
				return connect.NewError(connect.CodeUnavailable, cause)
			}
			return fmt.Errorf("receive from %s: %w", deviceID, err)
		}
		// A failed registry update is logged, not fatal: the next heartbeat retries.
		switch p := msg.GetPayload().(type) {
		case *agentv1.AgentMessage_Heartbeat:
			log.DebugContext(ctx, "heartbeat")
			if err := s.recheckCert(ctx, log, deviceID); err != nil {
				return err
			}
			if now, ok := s.rotationState(ctx); ok && now != rotation {
				log.InfoContext(ctx, "agent stream ended: the hub CA rotation moved on; the agent reconnects for its certificate and CAs")
				return errRotationMoved
			}
			if !pinned {
				pinned = s.pinCert(ctx, log, deviceID)
			}
			if err := s.registry.Heartbeat(ctx, deviceID, p.Heartbeat.GetUptime().AsDuration()); err != nil {
				log.WarnContext(ctx, "record heartbeat", "err", err)
			}
		case *agentv1.AgentMessage_Facts:
			log.DebugContext(ctx, "facts")
			sess.setCeiling(p.Facts.GetCeiling())
			if err := s.registry.ReportFacts(ctx, deviceID, p.Facts); err != nil {
				log.WarnContext(ctx, "record facts", "err", err)
			}
		case *agentv1.AgentMessage_ExecResult:
			sess.deliver(p.ExecResult)
		case *agentv1.AgentMessage_ProbeResult:
			sess.deliverProbe(p.ProbeResult)
		case *agentv1.AgentMessage_ScanResult:
			sess.deliverScan(p.ScanResult)
		case *agentv1.AgentMessage_MetricsBatch:
			s.recordMetrics(ctx, log, deviceID, p.MetricsBatch)
		case *agentv1.AgentMessage_LogLines:
			sess.deliverLogs(p.LogLines)
		case *agentv1.AgentMessage_ShellEvent:
			sess.deliverShell(p.ShellEvent)
		case *agentv1.AgentMessage_Hello:
			return connect.NewError(connect.CodeInvalidArgument, errors.New("duplicate Hello"))
		}
	}
}

// recheckCert re-runs the client certificate check of requireClientCert on an
// open stream. If the certificate is now revoked or unknown, and this hub can
// vouch for its store (authority returns nil: standalone, or the cluster
// leader within its term), it marks the device offline and returns the error
// that ends the stream. A hub that cannot vouch, or a failed lookup, keeps
// the stream: a follower or a hub catching up must not kick agents on stale
// data, and the next heartbeat checks again.
func (s *AgentStream) recheckCert(ctx context.Context, log *slog.Logger, deviceID string) error {
	if !trustedLeaf(ctx, s.ca) {
		log.InfoContext(ctx, "agent stream ended: its certificate is of a hub CA no longer trusted")
		if err := s.registry.markOffline(ctx, deviceID); err != nil {
			log.WarnContext(ctx, "mark device offline", "err", err)
		}
		return errUntrustedCA
	}
	serial, ok := serialFrom(ctx)
	if s.certs == nil || !ok {
		return nil
	}
	err := s.certs.Check(ctx, serial, deviceID)
	revoked := errors.Is(err, store.ErrCertRevoked)
	switch {
	case err == nil:
		return nil
	case !revoked && !errors.Is(err, store.ErrNotFound):
		log.WarnContext(ctx, "recheck client certificate", "err", err)
		return nil
	case s.authority() != nil:
		return nil
	}
	reason := "certificate unknown"
	if revoked {
		reason = "certificate revoked"
	}
	log.InfoContext(ctx, "agent stream ended: "+reason)
	if err := s.registry.markOffline(ctx, deviceID); err != nil {
		log.WarnContext(ctx, "mark device offline", "err", err)
	}
	return certRejection(revoked)
}

// markOffline marks one online device offline now and publishes
// device.offline, the transition Sweep makes for a silent device: the same
// MarkDevicesOffline command a clustered leader's sweep writes, the same
// cleanup of its presence memory, the same event. Only a standalone hub or a
// clustered leader (which holds presence memory) writes; elsewhere it does
// nothing. It lives here rather than in registry.go only to keep this change
// apart from concurrent registry work; it belongs next to Sweep.
func (r *Registry) markOffline(ctx context.Context, deviceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.replicated {
		r.liveMu.Lock()
		leading := r.seen != nil
		_, dirty := r.dirty[deviceID]
		r.liveMu.Unlock()
		if !leading {
			return nil
		}
		if dirty {
			if err := r.flushLocked(ctx); err != nil {
				return err
			}
		}
	}
	devs, err := r.devices.MarkDevicesOffline(ctx, []string{deviceID})
	if err != nil {
		return err
	}
	if r.replicated {
		r.liveMu.Lock()
		for _, d := range devs {
			delete(r.seen, d.ID)
		}
		r.liveMu.Unlock()
	}
	for _, d := range devs {
		r.publish(ctx, Event{Type: EventDeviceOffline, Device: d})
	}
	return nil
}

// certPinner is the part of store.Certs that pinCert needs.
type certPinner interface {
	Fingerprint(ctx context.Context, serial, deviceID string) (string, error)
	Pin(ctx context.Context, serial, deviceID, fingerprint, caFP string, now time.Time) (store.PinOutcome, error)
}

// auditAppender is the part of store.Audit that pinCert needs.
type auditAppender interface {
	Append(ctx context.Context, e store.AuditEntry) (int64, error)
}

// ActionCertMismatch is the audit action of a client certificate that is not
// the one recorded for its serial (see AgentStream.pinCert).
const ActionCertMismatch = "agent.cert_mismatch"

// pinCert records the fingerprint of the stream's client certificate, and
// its CA's, when none is recorded for its serial: trust on first use, for a
// certificate issued before the hub recorded fingerprints at enrollment
// (store.CertPinsSchema). A hub CA rotation renews only a certificate whose exact
// fingerprint is recorded, since its serial and device ID are in every copy
// of the database. A certificate whose serial has another fingerprint was
// minted by someone else with the CA key: the first sighting is recorded on
// the certificate and in the audit log.
//
// Only a hub that can vouch for its store pins (see Registry.certAuthority).
// It reports whether the certificate is settled: pinned, matching, or its
// mismatch recorded. Connect calls it again on every heartbeat until it is,
// so a stream that was open when the cluster migrated is pinned too.
func (s *AgentStream) pinCert(ctx context.Context, log *slog.Logger, deviceID string) bool {
	serial, ok := serialFrom(ctx)
	chain, hasChain := chainFrom(ctx)
	if s.pins == nil || !ok || !hasChain {
		return true
	}
	if s.authority() != nil {
		return false
	}
	leaf := chain[0]
	fp := pki.FingerprintHex(leaf)
	recorded, err := s.pins.Fingerprint(ctx, serial, deviceID)
	switch {
	case errors.Is(err, store.ErrSchemaTooOld):
		return false
	case err != nil:
		log.WarnContext(ctx, "read the client certificate's recorded fingerprint", "err", err)
		return false
	case recorded == fp:
		return true
	}
	var caFP string
	if len(chain) > 1 {
		caFP = pki.FingerprintHex(chain[len(chain)-1])
	}
	if recorded == "" {
		// During a hub CA rotation an old-CA certificate is not pinned on
		// first use: renewal needs a pin from before the rotation, which a
		// certificate minted with a stolen old key cannot have.
		if rot, ok := s.activeRotation(ctx); ok && caFP != rot.NewCAFP {
			return true
		}
	}
	outcome, err := s.pins.Pin(ctx, serial, deviceID, fp, caFP, s.now())
	switch {
	case err != nil:
		log.WarnContext(ctx, "record the client certificate's fingerprint", "err", err)
		return false
	case outcome == store.Pinned:
		log.InfoContext(ctx, "recorded the client certificate's fingerprint", "serial", serial)
	case outcome == store.PinMismatch:
		// It works until the CA is rotated, which does not renew it.
		log.WarnContext(ctx, "agent presented a certificate that is not the one recorded for its serial: "+
			"someone minted it with the hub CA key; a hub CA rotation will not renew it",
			"serial", serial, "fingerprint", fp)
		s.auditMismatch(ctx, log, deviceID, serial, fp, recorded)
	}
	return true
}

func (s *AgentStream) auditMismatch(ctx context.Context, log *slog.Logger, deviceID, serial, fp, recorded string) {
	if s.audit == nil {
		return
	}
	detail, err := json.Marshal(map[string]string{"serial": serial, "fingerprint": fp, "recorded_fingerprint": recorded})
	if err != nil {
		return
	}
	if _, err := s.audit.Append(ctx, store.AuditEntry{
		TS: s.now(), ActorKind: "agent", ActorID: deviceID, Action: ActionCertMismatch, Target: deviceID,
		Decision: policy.Deny, Result: "client certificate is not the one recorded for its serial", Detail: detail,
	}); err != nil {
		log.WarnContext(ctx, "audit a certificate mismatch", "err", err)
	}
}
