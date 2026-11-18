// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"fmt"
	"strings"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/integrations/prometheus"
	"github.com/gvart/hearth/internal/store"
)

// AutomationDevices feeds the registry's online and offline events to the
// automations' device trigger.
func AutomationDevices(reg *Registry) automation.DeviceEvents { return registryEvents{reg} }

type registryEvents struct{ reg *Registry }

// WatchDevices implements automation.DeviceEvents. A subscription the bus
// ends (the watcher fell behind, or leadership moved) is renewed at once.
func (e registryEvents) WatchDevices(ctx context.Context, fn func(automation.DeviceEvent)) error {
	for ctx.Err() == nil {
		ch, unsubscribe := e.reg.Subscribe()
		watchDevices(ctx, ch, fn)
		unsubscribe()
	}
	return nil
}

// watchDevices passes on presence events from ch until ch is closed or ctx
// is done.
func watchDevices(ctx context.Context, ch <-chan Event, fn func(automation.DeviceEvent)) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if ev.Type != EventDeviceOnline && ev.Type != EventDeviceOffline {
				continue
			}
			fn(automation.DeviceEvent{
				ID: ev.Device.ID, Name: ev.Device.Name, Hostname: ev.Device.Hostname,
				Online: ev.Type == EventDeviceOnline,
			})
		}
	}
}

// AutomationMetrics reads the metric trigger's values from Prometheus. It is
// nil when no Prometheus is configured.
func AutomationMetrics(st *store.Store, prom *prometheus.Reader) automation.Metrics {
	if prom == nil {
		return nil
	}
	return promMetrics{devices: st.Devices(), prom: prom}
}

type promMetrics struct {
	devices store.Devices
	prom    *prometheus.Reader
}

// DeviceMetric implements automation.Metrics.
func (m promMetrics) DeviceMetric(ctx context.Context, device, metric string) (float64, error) {
	d, err := m.findDevice(ctx, device)
	if err != nil {
		return 0, err
	}
	inst, err := m.prom.Instance(ctx, promDevice(d))
	if err != nil {
		return 0, fmt.Errorf("device %s: %w", device, err)
	}
	return m.prom.Current(ctx, inst, metric)
}

// Query implements automation.Metrics.
func (m promMetrics) Query(ctx context.Context, promql string) ([]float64, error) {
	return m.prom.Values(ctx, promql)
}

// findDevice returns the device whose id, name or hostname is ref.
func (m promMetrics) findDevice(ctx context.Context, ref string) (store.Device, error) {
	all, err := m.devices.List(ctx)
	if err != nil {
		return store.Device{}, err
	}
	for _, d := range all {
		if d.ID == ref || d.Name == ref || strings.EqualFold(d.Hostname, ref) {
			return d, nil
		}
	}
	return store.Device{}, fmt.Errorf("device %s: %w", ref, store.ErrNotFound)
}
