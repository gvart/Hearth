// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"fmt"
	"strings"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/integrations/prometheus"
	"github.com/gvart/hearth/internal/metrics"
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

// AutomationNetwork feeds the registry's network discovery events to the
// automations' network trigger.
func AutomationNetwork(reg *Registry) automation.NetworkEvents { return registryEvents{reg} }

// WatchNetwork implements automation.NetworkEvents, renewing a subscription
// the bus ends as WatchDevices does. A host marked known or ignored, or one
// of an enrolled device's interfaces, is silenced.
func (e registryEvents) WatchNetwork(ctx context.Context, fn func(automation.NetworkEvent)) error {
	for ctx.Err() == nil {
		ch, unsubscribe := e.reg.Subscribe()
		e.watchNetwork(ctx, ch, fn)
		unsubscribe()
	}
	return nil
}

// watchNetwork passes on new and returned hosts from ch until ch is closed
// or ctx is done.
func (e registryEvents) watchNetwork(ctx context.Context, ch <-chan Event, fn func(automation.NetworkEvent)) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if ev.Host == nil || (ev.Type != discovery.EventNew && ev.Type != discovery.EventReturned) {
				continue
			}
			h := ev.Host
			silenced := h.State != store.HostUnreviewed
			if !silenced {
				// A read of the local store; a failure only leaves the host
				// unsilenced.
				devs, err := e.reg.devices.List(ctx)
				silenced = err == nil && deviceMACs(devs)[h.MAC] != ""
			}
			fn(automation.NetworkEvent{
				Returned: ev.Type == discovery.EventReturned,
				MAC:      h.MAC, IP: h.IP, Vendor: h.Vendor, Name: h.Hostname,
				Silenced: silenced,
			})
		}
	}
}

// AutomationMetrics reads the metric trigger's values from Prometheus, or,
// when none is configured, a device's values from the hub's own metrics ms
// (which answer no PromQL). It is nil when there is neither.
func AutomationMetrics(st *store.Store, prom *prometheus.Reader, ms *metrics.Store) automation.Metrics {
	switch {
	case prom != nil:
		return promMetrics{devices: st.Devices(), prom: prom}
	case ms != nil:
		return builtinMetrics{devices: st.Devices(), metrics: ms}
	}
	return nil
}

type promMetrics struct {
	devices store.Devices
	prom    *prometheus.Reader
}

// DeviceMetric implements automation.Metrics.
func (m promMetrics) DeviceMetric(ctx context.Context, device, metric string) (float64, error) {
	d, err := findDevice(ctx, m.devices, device)
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
func findDevice(ctx context.Context, devices store.Devices, ref string) (store.Device, error) {
	all, err := devices.List(ctx)
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
