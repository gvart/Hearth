// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"
)

// defaultMetricEvery is how often a metric trigger reads its value.
const defaultMetricEvery = 30 * time.Second

// metricTrigger fires when a metric has been above or below a threshold for
// a duration: a device's cpu, memory or disk, or any PromQL query.
type metricTrigger struct {
	device, metric, query string
	above                 bool
	threshold             float64
	timing                pollTiming
	metrics               Metrics
	clock                 Clock
	log                   *slog.Logger
}

func buildMetric(p Params, deps TriggerDeps) (Trigger, error) {
	var cfg struct {
		Device  string        `yaml:"device"`
		Metric  string        `yaml:"metric"`
		Query   string        `yaml:"query"`
		Above   *float64      `yaml:"above"`
		Below   *float64      `yaml:"below"`
		Every   time.Duration `yaml:"every"`
		For     time.Duration `yaml:"for"`
		Timeout time.Duration `yaml:"timeout"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	t := &metricTrigger{
		device: cfg.Device, metric: cfg.Metric, query: cfg.Query,
		metrics: deps.Metrics, clock: deps.Clock, log: deps.Log,
	}
	switch {
	case cfg.Query != "" && (cfg.Device != "" || cfg.Metric != ""):
		return nil, errors.New("set either query, or device and metric")
	case cfg.Query == "":
		if cfg.Device == "" {
			return nil, errors.New("device and metric, or query, are required")
		}
		switch cfg.Metric {
		case "cpu", "memory", "disk":
		default:
			return nil, fmt.Errorf("metric must be cpu, memory or disk, not %q", cfg.Metric)
		}
	}
	switch {
	case (cfg.Above == nil) == (cfg.Below == nil):
		return nil, errors.New("set exactly one of above and below")
	case cfg.Above != nil:
		t.above, t.threshold = true, *cfg.Above
	default:
		t.threshold = *cfg.Below
	}
	t.timing = pollTiming{Every: cfg.Every, For: cfg.For, Timeout: cfg.Timeout}
	if err := t.timing.check(defaultMetricEvery); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *metricTrigger) Describe() string {
	what := fmt.Sprintf("%s of device %s", t.metric, t.device)
	if t.query != "" {
		what = fmt.Sprintf("query %q", t.query)
	}
	cmp := "below"
	if t.above {
		cmp = "above"
	}
	return fmt.Sprintf("fires when %s is %s %s%s (checked every %s)",
		what, cmp, strconv.FormatFloat(t.threshold, 'g', -1, 64), forText(t.timing.For), t.timing.Every)
}

func (t *metricTrigger) Sample() map[string]any { return t.data(t.threshold) }

// data is what a metric trigger tells actions: the value past the threshold,
// and the device as the trigger names it, if it names one.
func (t *metricTrigger) data(v float64) map[string]any {
	d := map[string]any{"Value": v}
	if t.query == "" {
		d["Device"] = t.device
	}
	return d
}

func (t *metricTrigger) Watch(ctx context.Context, fire FireFunc) error {
	if t.metrics == nil {
		return errors.New("metric triggers need a Prometheus: start the hub with --prometheus-url")
	}
	var lastErr string
	return poller{clock: t.clock, every: t.timing.Every, hold: t.timing.For, bad: func(ctx context.Context) (map[string]any, bool) {
		v, held, err := t.crossed(ctx)
		// A value that cannot be read does not count as crossed: like
		// Prometheus alerts, missing data resets the duration. Log each new
		// error once, not on every check.
		switch {
		case err != nil && err.Error() != lastErr && ctx.Err() == nil:
			t.log.WarnContext(ctx, "metric trigger cannot read its value", "err", err)
			lastErr = err.Error()
		case err == nil:
			lastErr = ""
		}
		if !held {
			return nil, false
		}
		return t.data(v), true
	}}.watch(ctx, fire)
}

// crossed reads the value and reports whether it is past the threshold,
// and the value that is. For a query, any series past it counts.
func (t *metricTrigger) crossed(ctx context.Context) (float64, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, t.timing.Timeout)
	defer cancel()
	var values []float64
	if t.query != "" {
		var err error
		if values, err = t.metrics.Query(ctx, t.query); err != nil {
			return 0, false, err
		}
	} else {
		v, err := t.metrics.DeviceMetric(ctx, t.device, t.metric)
		if err != nil {
			return 0, false, err
		}
		values = []float64{v}
	}
	for _, v := range values {
		if (t.above && v > t.threshold) || (!t.above && v < t.threshold) {
			return v, true, nil
		}
	}
	return 0, false, nil
}
