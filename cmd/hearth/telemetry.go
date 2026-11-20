// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/telemetry"
)

// defaultTelemetryEndpoint is the collector opted-in hubs send their weekly
// anonymous usage stats to (docs/telemetry.md). Empty until the project runs
// one (deploy/telemetry-worker): opting in is then stored, and nothing is sent.
const defaultTelemetryEndpoint = ""

// telemetryOptions are the hub's telemetry flags.
type telemetryOptions struct {
	// mode is --telemetry / HEARTH_TELEMETRY: "off" overrides the admin's
	// answer; empty leaves telemetry to it.
	mode     string
	endpoint string
}

func addTelemetryFlags(cmd *cobra.Command, o *telemetryOptions) {
	cmd.Flags().StringVar(&o.mode, "telemetry", os.Getenv("HEARTH_TELEMETRY"),
		`"off" never sends anonymous usage stats, whatever the admin answered in the web UI (env HEARTH_TELEMETRY; see docs/telemetry.md)`)
	endpoint := defaultTelemetryEndpoint
	if v, ok := os.LookupEnv("HEARTH_TELEMETRY_ENDPOINT"); ok {
		endpoint = v
	}
	cmd.Flags().StringVar(&o.endpoint, "telemetry-endpoint", endpoint,
		"https URL opted-in usage stats are sent to; empty sends nothing (env HEARTH_TELEMETRY_ENDPOINT)")
}

// off parses the flags: whether telemetry is turned off on this hub.
func (o telemetryOptions) off() (bool, error) {
	off, err := telemetry.ParseMode(o.mode)
	if err != nil {
		return false, fmt.Errorf("--telemetry: %w", err)
	}
	if err := telemetry.CheckEndpoint(o.endpoint); err != nil {
		return false, fmt.Errorf("--telemetry-endpoint: %w", err)
	}
	return off, nil
}

// newTelemetrySender builds the sender. It names the integrations the flags
// turn on: kinds only, never their URLs.
func newTelemetrySender(opts hubOptions, off bool, st *store.Store, node *cluster.Node, log *slog.Logger) *telemetry.Sender {
	cfg := telemetry.Config{
		Store: st, Endpoint: opts.telemetry.endpoint, Off: off, Version: opts.version,
		Integrations: telemetryIntegrations(opts), Log: log,
	}
	if node != nil {
		cfg.Leader = node
	}
	return telemetry.New(cfg)
}

// telemetryIntegrations names the integrations the flags turn on.
func telemetryIntegrations(opts hubOptions) []string {
	var names []string
	for name, on := range map[string]bool{
		telemetry.Prometheus: opts.prometheusURL != "",
		telemetry.PiHole:     opts.piholeURL != "",
		telemetry.NetAlertX:  opts.netalertxURL != "",
		telemetry.Beszel:     opts.beszelURL != "",
		telemetry.DHCP:       len(opts.dhcpLeases) > 0,
		telemetry.Discovery:  len(opts.discoverSubnets) > 0,
		telemetry.Talos:      opts.talosconfig != "",
	} {
		if on {
			names = append(names, name)
		}
	}
	return names
}
