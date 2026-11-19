// SPDX-License-Identifier: AGPL-3.0-only

// Package telemetry sends the hub's opt-in anonymous usage stats: once a week,
// and shortly after the admin opts in, a few counts and names in one JSON
// POST. docs/telemetry.md lists exactly what is sent. Nothing is sent until
// the admin answers yes in the web UI, never with HEARTH_TELEMETRY=off, never
// without an endpoint, and in a cluster only by the leader.
package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// Interval is how often an opted-in hub sends.
const Interval = 7 * 24 * time.Hour

// Integration names: the only ones a payload may carry. They name a kind of
// integration, never a user-chosen name, URL or credential.
const (
	Prometheus = "prometheus"
	Kubernetes = "kubernetes"
	Proxmox    = "proxmox"
	PiHole     = "pihole"
	NetAlertX  = "netalertx"
	Beszel     = "beszel"
	DHCP       = "dhcp"
	Discovery  = "discovery"
)

var allowed = []string{Beszel, DHCP, Discovery, Kubernetes, NetAlertX, PiHole, Prometheus, Proxmox}

// Payload is everything sent, and nothing else may be. Its JSON keys are the
// collector's whole schema.
type Payload struct {
	InstallID    string   `json:"install_id"`
	Version      string   `json:"version"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	Devices      string   `json:"devices"`
	Integrations []string `json:"integrations"`
}

// Bucket turns a device count into the range sent instead of the count.
func Bucket(n int) string {
	switch {
	case n <= 0:
		return "0"
	case n <= 5:
		return "1-5"
	case n <= 20:
		return "6-20"
	case n <= 50:
		return "21-50"
	default:
		return "51+"
	}
}

// NewInstallID returns a random install ID (crypto/rand.Text: 26 base32
// characters). It is derived from nothing on the host.
func NewInstallID() string {
	return rand.Text()
}

// Leader tells whether this hub is the cluster leader.
type Leader interface {
	IsLeader() bool
}

// Config configures a Sender.
type Config struct {
	Store *store.Store
	// Endpoint is the collector's URL; empty sends nothing.
	Endpoint string
	// Off is HEARTH_TELEMETRY=off: nothing is ever sent.
	Off bool
	// Leader is nil on a single hub, which always sends.
	Leader  Leader
	Version string
	// Integrations names the integrations the hub's flags turn on; Kubernetes
	// and Proxmox are added when the store holds any.
	Integrations []string
	// Client sends the payload; nil uses a client with a short timeout.
	Client *http.Client
	// Check is how often the stored answer is read; default a minute.
	Check time.Duration
	Log   *slog.Logger
	Now   func() time.Time
}

// Sender sends the payload while the admin's answer is yes.
type Sender struct {
	cfg        Config
	noEndpoint bool // logged once
}

// New returns a Sender for cfg.
func New(cfg Config) *Sender {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Check <= 0 {
		cfg.Check = time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Sender{cfg: cfg}
}

// Run checks the stored answer every cfg.Check and sends when due, until ctx
// ends.
func (s *Sender) Run(ctx context.Context) error {
	if s.cfg.Off {
		return nil
	}
	t := time.NewTicker(s.cfg.Check)
	defer t.Stop()
	for {
		s.Tick(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Tick sends once if telemetry is on, this hub leads and a week has passed
// since the last attempt for the current install ID. It reports whether it
// sent. A failed send counts as an attempt: the next is a week later.
func (s *Sender) Tick(ctx context.Context) bool {
	if s.cfg.Off || (s.cfg.Leader != nil && !s.cfg.Leader.IsLeader()) {
		return false
	}
	set, err := s.cfg.Store.Telemetry().Get(ctx)
	if err != nil {
		s.cfg.Log.DebugContext(ctx, "telemetry: read setting", "err", err)
		return false
	}
	if !set.Enabled || set.InstallID == "" {
		return false
	}
	now := s.cfg.Now()
	if !set.LastSent.IsZero() && now.Sub(set.LastSent) < Interval {
		return false
	}
	if s.cfg.Endpoint == "" {
		if !s.noEndpoint {
			s.noEndpoint = true
			s.cfg.Log.InfoContext(ctx, "telemetry is on, but this build has no collector endpoint: nothing is sent")
		}
		return false
	}
	p, err := s.payload(ctx, set.InstallID)
	if err != nil {
		s.cfg.Log.DebugContext(ctx, "telemetry: build payload", "err", err)
		return false
	}
	if err := s.post(ctx, p); err != nil {
		s.cfg.Log.DebugContext(ctx, "telemetry: send", "err", err)
	}
	if err := s.cfg.Store.Telemetry().MarkSent(ctx, set.InstallID, now); err != nil {
		s.cfg.Log.DebugContext(ctx, "telemetry: record send", "err", err)
	}
	return true
}

// payload reads only what the payload holds: counts, never names.
func (s *Sender) payload(ctx context.Context, installID string) (Payload, error) {
	c, err := s.cfg.Store.Telemetry().Counts(ctx)
	if err != nil {
		return Payload{}, err
	}
	names := slices.Clone(s.cfg.Integrations)
	if c.KubeClusters > 0 {
		names = append(names, Kubernetes)
	}
	if c.ProxmoxServers > 0 {
		names = append(names, Proxmox)
	}
	return Payload{
		InstallID:    installID,
		Version:      s.cfg.Version,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Devices:      Bucket(c.Devices),
		Integrations: Allowed(names),
	}, nil
}

// Allowed keeps the known integration names of names, sorted and once each.
func Allowed(names []string) []string {
	out := []string{}
	for _, n := range names {
		if slices.Contains(allowed, n) && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

func (s *Sender) post(ctx context.Context, p Payload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.cfg.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("collector answered %s", resp.Status)
	}
	return nil
}

// ErrBadMode is returned by ParseMode for a value other than "" or "off".
var ErrBadMode = errors.New(`only "off" is accepted; opt in from the web UI`)

// ParseMode reads --telemetry / HEARTH_TELEMETRY: "off" turns telemetry off
// whatever the stored answer; empty leaves it to the admin's answer.
func ParseMode(v string) (off bool, err error) {
	switch v {
	case "":
		return false, nil
	case "off":
		return true, nil
	default:
		return false, fmt.Errorf("%q: %w", v, ErrBadMode)
	}
}

// CheckEndpoint accepts an empty endpoint (send nothing) or an https URL.
func CheckEndpoint(v string) error {
	if v == "" {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%q: want an https:// URL", v)
	}
	return nil
}
