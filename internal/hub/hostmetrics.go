// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/gvart/hearth/internal/metrics"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// maxMetricsBatch bounds the samples kept from one MetricsBatch: an agent
// sends one of each known metric per batch.
const maxMetricsBatch = 64

// recordMetrics stores the known, finite samples of a MetricsBatch, stamped
// with the hub's clock: an agent's clock may be off, and it sends each
// batch as soon as it is collected. A failed write is logged, not fatal.
func (s *AgentStream) recordMetrics(ctx context.Context, log *slog.Logger, deviceID string, b *agentv1.MetricsBatch) {
	if s.metrics == nil {
		return
	}
	var out []metrics.Sample
	for _, smp := range b.GetSamples() {
		v := smp.GetValue()
		if len(out) == maxMetricsBatch || !metrics.IsKnown(smp.GetName()) || math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		out = append(out, metrics.Sample{Name: smp.GetName(), Value: v})
	}
	if err := s.metrics.Write(ctx, deviceID, s.now(), out); err != nil {
		log.WarnContext(ctx, "record metrics", "err", err)
	}
}

// builtinCharts fills out with a device's series from the hub's own metrics
// over start..end. No series with data is status no_data.
func (a *api) builtinCharts(ctx context.Context, out *MetricsJSON, deviceID string, names []string, start, end time.Time) error {
	series, err := a.metrics.Query(ctx, deviceID, names, start, end, metricsStep(end.Sub(start)))
	if err != nil {
		return err
	}
	out.Charts = append(out.Charts, builtinChartList(series)...)
	out.Start, out.End = start.UnixMilli(), end.UnixMilli()
	out.Status = metricsOK
	if len(out.Charts) == 0 {
		out.Status = metricsNoData
		out.Message = "no metrics from this device in this range yet; an older agent sends none"
	}
	return nil
}

// builtinChartList is series as charts, in chart order, leaving out metrics
// with no points.
func builtinChartList(series map[string][]metrics.Point) []ChartJSON {
	out := []ChartJSON{}
	for _, k := range metrics.Known {
		pts := series[k.Key]
		if len(pts) == 0 {
			continue
		}
		c := ChartJSON{Key: k.Key, Name: k.Name, Unit: k.Unit, Points: make([][2]float64, 0, len(pts))}
		for _, p := range pts {
			c.Points = append(c.Points, [2]float64{float64(p.T.UnixMilli()), p.V})
		}
		out = append(out, c)
	}
	return out
}

const (
	// sparklineWindow is the time a device list sparkline spans.
	sparklineWindow = time.Hour
	// sparklineStep gives a sparkline 30 points, read from one-minute rollups.
	sparklineStep = 2 * time.Minute
)

// SparklinesJSON is the body of GET /metrics/sparklines.
type SparklinesJSON struct {
	// Start and End bound the sparklines, in unix milliseconds.
	Start int64 `json:"start"`
	End   int64 `json:"end"`
	// Devices holds the charts of each device with recent metrics, by ID.
	Devices map[string][]ChartJSON `json:"devices"`
}

// metricsSparklines serves the last hour of every device's built-in metrics,
// coarsely, so the device list draws its sparklines from one request. It never
// reads Prometheus, which would cost a remote query per device per refresh.
func (a *api) metricsSparklines(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	end := a.now()
	start := end.Add(-sparklineWindow)
	out := SparklinesJSON{Start: start.UnixMilli(), End: end.UnixMilli(), Devices: map[string][]ChartJSON{}}
	if a.metrics == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	devices, err := a.store.Devices().List(ctx)
	if err != nil {
		a.log.ErrorContext(ctx, "list devices", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot list devices")
		return
	}
	for _, d := range devices {
		series, err := a.metrics.Query(ctx, d.ID, nil, start, end, sparklineStep)
		if err != nil {
			a.log.ErrorContext(ctx, "read metrics", "device_id", d.ID, "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "cannot read metrics")
			return
		}
		if charts := builtinChartList(series); len(charts) > 0 {
			out.Devices[d.ID] = charts
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// latestMaxAge is how old the newest sample may be for the metric trigger to
// use it: a few of the agents' 15 s intervals.
const latestMaxAge = time.Minute

// builtinMetrics reads the metric trigger's device values from the hub's own
// metrics, when no Prometheus is configured. In an AP cluster each master
// keeps the metrics of the agents streaming to it, so the values of a device
// whose agent streams to another live master are read from that master
// (agents forwards the read).
type builtinMetrics struct {
	devices store.Devices
	metrics *metrics.Store
	agents  *Agents
}

// DeviceMetric implements automation.Metrics.
func (m builtinMetrics) DeviceMetric(ctx context.Context, device, metric string) (float64, error) {
	d, err := findDevice(ctx, m.devices, device)
	if err != nil {
		return 0, err
	}
	if m.agents != nil {
		if v, ok, err := m.agents.remoteMetric(ctx, d.ID, metric); ok {
			return v, err
		}
	}
	return m.metrics.Latest(ctx, d.ID, metric, latestMaxAge)
}

// errNoPromQL refuses a PromQL query without a Prometheus.
var errNoPromQL = errors.New("PromQL queries need a Prometheus: start the hub with --prometheus-url")

// Query implements automation.Metrics.
func (builtinMetrics) Query(context.Context, string) ([]float64, error) { return nil, errNoPromQL }
