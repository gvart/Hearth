// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"log/slog"
	"time"
)

// Clock is the time source of the triggers that wait: real time in the hub, a
// fake one in tests.
type Clock interface {
	Now() time.Time
	// After sends the time once d has passed.
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// DeviceEvent is a device going online or offline.
type DeviceEvent struct {
	ID       string
	Name     string
	Hostname string
	Online   bool
}

// DeviceEvents tells the device trigger about presence changes: the hub's
// device registry.
type DeviceEvents interface {
	// WatchDevices calls fn for every device that goes online or offline,
	// until ctx is done.
	WatchDevices(ctx context.Context, fn func(DeviceEvent)) error
}

// Metrics reads current metric values for the metric trigger: the hub's
// Prometheus.
type Metrics interface {
	// DeviceMetric returns the current value of metric (cpu, memory or disk,
	// in percent) of the device with this id, name or hostname.
	DeviceMetric(ctx context.Context, device, metric string) (float64, error)
	// Query evaluates PromQL now and returns the value of each series.
	Query(ctx context.Context, promql string) ([]float64, error)
}

// TriggerDeps are what the triggers watch. A nil Devices or Metrics leaves
// the triggers that need it loadable (for a dry run), but they stop with an
// error when the hub starts them.
type TriggerDeps struct {
	// Clock defaults to real time.
	Clock   Clock
	Devices DeviceEvents
	Metrics Metrics
	Log     *slog.Logger
}

// Triggers returns the trigger types that watch the lab, to add to Builtin's:
// device, metric, http, dns, tcp and schedule.
func Triggers(deps TriggerDeps) map[string]Builder[Trigger] {
	if deps.Clock == nil {
		deps.Clock = realClock{}
	}
	if deps.Log == nil {
		deps.Log = slog.New(slog.DiscardHandler)
	}
	return map[string]Builder[Trigger]{
		"device":   func(p Params) (Trigger, error) { return buildDevice(p, deps) },
		"metric":   func(p Params) (Trigger, error) { return buildMetric(p, deps) },
		"http":     func(p Params) (Trigger, error) { return buildHTTPCheck(p, deps) },
		"dns":      func(p Params) (Trigger, error) { return buildDNSCheck(p, deps) },
		"tcp":      func(p Params) (Trigger, error) { return buildTCPCheck(p, deps) },
		"schedule": func(p Params) (Trigger, error) { return buildSchedule(p, deps) },
	}
}
