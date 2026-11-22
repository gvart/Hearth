// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// EventNetworkScanDone is published on /api/v1/events when a scan asked for
// with POST /api/v1/network/scan ends.
const EventNetworkScanDone = "network.scan.done"

// NetworkScanner runs one network scan asked for by an actor:
// *discovery.Scanner.
type NetworkScanner interface {
	ScanAs(ctx context.Context, actorKind, actorID string, accepted func()) (discovery.ScanSummary, error)
}

// NetworkScanJSON is the data of a network.scan.done event: the scan's id,
// as POST /api/v1/network/scan answered it, and its counts, or why it failed.
type NetworkScanJSON struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Hosts      int    `json:"hosts"`
	New        int    `json:"new"`
	Returned   int    `json:"returned"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// NetworkScanStartedJSON is the answer of POST /api/v1/network/scan: the id
// the scan's network.scan.done event carries.
type NetworkScanStartedJSON struct {
	ID string `json:"id"`
}

// NetworkScans runs the scans admins ask for, in the background of the hub:
// Run owns them and stops them with the hub.
type NetworkScans struct {
	scanner NetworkScanner
	reg     *Registry
	log     *slog.Logger
	reqs    chan scanRequest
}

type scanRequest struct {
	id, actorKind, actorID string
	// decided gets nil once policy allowed the scan, or the error it ended
	// with before.
	decided chan error
}

// NewNetworkScans returns the runner of the scans of scanner asked for over
// the API, which publishes their ends on reg's UI feed.
func NewNetworkScans(scanner NetworkScanner, reg *Registry, log *slog.Logger) *NetworkScans {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &NetworkScans{scanner: scanner, reg: reg, log: log, reqs: make(chan scanRequest)}
}

// Run runs the scans asked for until ctx is done, then waits for those
// still running, which ctx stops.
func (n *NetworkScans) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		select {
		case <-ctx.Done():
			return nil
		case req := <-n.reqs:
			wg.Go(func() { n.scan(ctx, req) })
		}
	}
}

// Start asks for a scan, and returns its id once policy has allowed it, or
// the error it failed with before running: denied, already running
// (discovery ErrScanRunning) or otherwise. The scan itself runs on in Run,
// and its network.scan.done event carries the id.
func (n *NetworkScans) Start(ctx context.Context, actorKind, actorID string) (string, error) {
	req := scanRequest{
		id: strings.ToLower(rand.Text()), actorKind: actorKind, actorID: actorID, decided: make(chan error, 1),
	}
	select {
	case n.reqs <- req:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	select {
	case err := <-req.decided:
		if err != nil {
			return "", err
		}
		return req.id, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (n *NetworkScans) scan(ctx context.Context, req scanRequest) {
	accepted := false
	sum, err := n.scanner.ScanAs(ctx, req.actorKind, req.actorID, func() {
		accepted = true
		req.decided <- nil
	})
	if !accepted {
		req.decided <- err
		return
	}
	ev := NetworkScanJSON{
		Type: EventNetworkScanDone, ID: req.id, Hosts: sum.Hosts, New: sum.New, Returned: sum.Returned,
		DurationMS: sum.Duration.Milliseconds(),
	}
	if err != nil {
		if ctx.Err() == nil {
			n.log.WarnContext(ctx, "network scan failed", "actor", req.actorKind+"/"+req.actorID, "err", err)
		}
		ev = NetworkScanJSON{Type: EventNetworkScanDone, ID: req.id, Error: err.Error()}
	}
	n.reg.ScanDone(ev)
}

// ScanDone publishes the end of a scan asked for over the API on the UI's
// feed only: automations have their own network triggers.
func (r *Registry) ScanDone(ev NetworkScanJSON) {
	r.ui.publish(Event{Type: ev.Type, Scan: &ev})
}

// scanNetwork serves POST /api/v1/network/scan: it starts one scan of the
// configured subnets or, when there are none, of the hub's own LANs, through
// policy (network.scan, actor web), and answers 202 with the scan's id once
// policy has allowed it. The scan runs on this hub; its end is published on
// /api/v1/events as network.scan.done, with the same id. A scan already
// running answers 409.
func (a *api) scanNetwork(w http.ResponseWriter, r *http.Request) {
	if a.scans == nil {
		writeError(w, http.StatusServiceUnavailable, "not_configured", "this hub runs no network scans")
		return
	}
	id, err := a.scans.Start(r.Context(), policy.ActorWeb, remoteHost(r))
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, NetworkScanStartedJSON{ID: id})
	case errors.Is(err, discovery.ErrScanRunning):
		writeError(w, http.StatusConflict, "scan_running", "a network scan is already running")
	case errors.Is(err, discovery.ErrNoSubnet):
		writeError(w, http.StatusConflict, "no_subnet",
			"nothing to scan: the hub has no private IPv4 address and no --discover-subnet")
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	case r.Context().Err() != nil:
	default:
		a.log.ErrorContext(r.Context(), "start network scan", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot start the network scan")
	}
}
