// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"log/slog"
	"math"
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
	for _, k := range metrics.Known {
		pts := series[k.Key]
		if len(pts) == 0 {
			continue
		}
		c := ChartJSON{Key: k.Key, Name: k.Name, Unit: k.Unit, Points: make([][2]float64, 0, len(pts))}
		for _, p := range pts {
			c.Points = append(c.Points, [2]float64{float64(p.T.UnixMilli()), p.V})
		}
		out.Charts = append(out.Charts, c)
	}
	out.Start, out.End = start.UnixMilli(), end.UnixMilli()
	out.Status = metricsOK
	if len(out.Charts) == 0 {
		out.Status = metricsNoData
		out.Message = "no metrics from this device in this range yet; agents send them from protocol 1.4 on"
	}
	return nil
}

// latestMaxAge is how old the newest sample may be for the metric trigger to
// use it: a few of the agents' 15 s intervals.
const latestMaxAge = time.Minute

// builtinMetrics reads the metric trigger's device values from the hub's own
// metrics, when no Prometheus is configured.
type builtinMetrics struct {
	devices store.Devices
	metrics *metrics.Store
}

// DeviceMetric implements automation.Metrics.
func (m builtinMetrics) DeviceMetric(ctx context.Context, device, metric string) (float64, error) {
	d, err := findDevice(ctx, m.devices, device)
	if err != nil {
		return 0, err
	}
	return m.metrics.Latest(ctx, d.ID, metric, latestMaxAge)
}

// errNoPromQL refuses a PromQL query without a Prometheus.
var errNoPromQL = errors.New("PromQL queries need a Prometheus: start the hub with --prometheus-url")

// Query implements automation.Metrics.
func (builtinMetrics) Query(context.Context, string) ([]float64, error) { return nil, errNoPromQL }
