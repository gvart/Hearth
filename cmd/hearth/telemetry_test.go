// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"

	"github.com/spf13/cobra"
)

// HEARTH_TELEMETRY and --telemetry turn telemetry off; the flag beats the
// environment, and nothing but "off" is accepted.
func TestTelemetryFlags(t *testing.T) {
	for _, tt := range []struct {
		name, env, endpointEnv string
		args                   []string
		off, ok                bool
		endpoint               string
	}{
		{name: "default", ok: true, endpoint: defaultTelemetryEndpoint},
		{name: "env off", env: "off", off: true, ok: true},
		{name: "flag off", args: []string{"--telemetry=off"}, off: true, ok: true},
		{name: "flag beats env", env: "bogus", args: []string{"--telemetry=off"}, off: true, ok: true},
		{name: "env on is refused", env: "on"},
		{name: "env endpoint", endpointEnv: "https://t.example.com/v1", ok: true, endpoint: "https://t.example.com/v1"},
		{name: "flag endpoint", args: []string{"--telemetry-endpoint=https://f.example.com"}, ok: true, endpoint: "https://f.example.com"},
		{name: "plain http endpoint is refused", args: []string{"--telemetry-endpoint=http://t.example.com"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HEARTH_TELEMETRY", tt.env)
			if tt.endpointEnv != "" {
				t.Setenv("HEARTH_TELEMETRY_ENDPOINT", tt.endpointEnv)
			}
			var o telemetryOptions
			cmd := &cobra.Command{}
			addTelemetryFlags(cmd, &o)
			if err := cmd.ParseFlags(tt.args); err != nil {
				t.Fatal(err)
			}
			off, err := o.off()
			if (err == nil) != tt.ok || off != tt.off {
				t.Fatalf("off() = %v, %v; want off %v, ok %v", off, err, tt.off, tt.ok)
			}
			if tt.ok && tt.endpoint != "" && o.endpoint != tt.endpoint {
				t.Errorf("endpoint = %q, want %q", o.endpoint, tt.endpoint)
			}
		})
	}
}
