// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gvart/hearth/internal/integrations/prometheus"
	"github.com/gvart/hearth/internal/store"
)

// Metrics statuses. Anything but ok comes with no charts and is not an error:
// the UI shows why there is nothing to draw.
const (
	metricsOK            = "ok"
	metricsNotConfigured = "not_configured"
	metricsUnreachable   = "unreachable"
	metricsNoTarget      = "no_target"
)

const (
	defaultMetricsRange = time.Hour
	minMetricsRange     = 5 * time.Minute
	maxMetricsRange     = 7 * 24 * time.Hour
	// metricsPoints is roughly how many points a chart gets.
	metricsPoints  = 120
	minMetricsStep = 15 * time.Second
)

// MetricsJSON is the body of GET /devices/{id}/metrics.
type MetricsJSON struct {
	Source string `json:"source"`
	// Status is ok, not_configured, unreachable or no_target.
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	// Instance is the Prometheus instance label the device mapped to.
	Instance string `json:"instance,omitempty"`
	// Start and End bound the charted range, in unix milliseconds; set when
	// Status is ok.
	Start  int64       `json:"start,omitempty"`
	End    int64       `json:"end,omitempty"`
	Charts []ChartJSON `json:"charts"`
}

// ChartJSON is one chart series; each point is [unix milliseconds, value].
type ChartJSON struct {
	Key    string       `json:"key"`
	Name   string       `json:"name"`
	Unit   string       `json:"unit"`
	Points [][2]float64 `json:"points"`
}

// deviceMetrics serves a device's chart series from Prometheus. A missing or
// unreachable Prometheus, or one that does not scrape the device, is a normal
// answer with a status, never a 5xx.
func (a *api) deviceMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	window := defaultMetricsRange
	if v := r.URL.Query().Get("range"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < minMetricsRange || d > maxMetricsRange {
			writeError(w, http.StatusBadRequest, "bad_request", "range must be a duration from 5m to 168h")
			return
		}
		window = d
	}
	d, err := a.store.Devices().Get(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such device")
		return
	}
	if err != nil {
		a.log.ErrorContext(ctx, "get device", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot get device")
		return
	}
	out := MetricsJSON{Source: "prometheus", Charts: []ChartJSON{}}
	if a.prom == nil {
		out.Status = metricsNotConfigured
		out.Message = "no Prometheus endpoint configured (hearth hub --prometheus-url)"
		writeJSON(w, http.StatusOK, out)
		return
	}
	inst, err := a.prom.Instance(ctx, promDevice(d))
	if errors.Is(err, prometheus.ErrNoTarget) {
		out.Status = metricsNoTarget
		out.Message = "Prometheus has no node-exporter target for this device"
		writeJSON(w, http.StatusOK, out)
		return
	}
	var charts []prometheus.Chart
	end := a.now()
	start := end.Add(-window)
	if err == nil {
		out.Instance = inst
		charts, err = a.prom.Charts(ctx, inst, start, end, metricsStep(window))
	}
	if err != nil {
		a.log.WarnContext(ctx, "read prometheus", "device_id", d.ID, "err", err)
		out.Status = metricsUnreachable
		out.Message = "cannot read from Prometheus: " + err.Error()
		writeJSON(w, http.StatusOK, out)
		return
	}
	out.Status = metricsOK
	out.Start, out.End = start.UnixMilli(), end.UnixMilli()
	for _, c := range charts {
		pts := make([][2]float64, 0, len(c.Samples))
		for _, s := range c.Samples {
			pts = append(pts, [2]float64{float64(s.T.UnixMilli()), s.V})
		}
		out.Charts = append(out.Charts, ChartJSON{Key: c.Key, Name: c.Name, Unit: c.Unit, Points: pts})
	}
	writeJSON(w, http.StatusOK, out)
}

// metricsStep spreads window over about metricsPoints points, in whole seconds.
func metricsStep(window time.Duration) time.Duration {
	return max((window / metricsPoints).Truncate(time.Second), minMetricsStep)
}

// promDevice is what Prometheus target mapping knows of d: its hostname and
// the addresses from its facts.
func promDevice(d store.Device) prometheus.Device {
	out := prometheus.Device{Hostname: d.Hostname}
	var f Facts
	if json.Unmarshal(d.Facts, &f) == nil {
		if out.Hostname == "" {
			out.Hostname = f.Hostname
		}
		for _, i := range f.Interfaces {
			out.Addrs = append(out.Addrs, i.IPs...)
		}
	}
	return out
}
