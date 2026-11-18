// SPDX-License-Identifier: AGPL-3.0-only

package prometheus

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

// ErrNoTarget means Prometheus has no node-exporter target for a device.
var ErrNoTarget = errors.New("no node-exporter target matches this device")

// Device identifies a Hearth device to Prometheus: its hostname and addresses.
type Device struct {
	Hostname string
	// Addrs are the device's IP addresses; CIDR suffixes are ignored.
	Addrs []string
}

// Reader maps devices to node-exporter targets and reads their chart series.
type Reader struct {
	q   Querier
	now func() time.Time
}

// NewReader returns a Reader over q.
func NewReader(q Querier) *Reader {
	return &Reader{q: q, now: time.Now}
}

// Instance returns the value of the `instance` label of the node-exporter
// target for d. It looks at node_uname_info and prefers a target whose
// `nodename` is d's hostname, then one whose `instance` host is d's hostname
// or one of its addresses. It returns ErrNoTarget if none matches.
func (r *Reader) Instance(ctx context.Context, d Device) (string, error) {
	infos, err := r.q.Query(ctx, "node_uname_info", r.now())
	if err != nil {
		return "", err
	}
	names := map[string]bool{}
	if h := strings.ToLower(strings.TrimSuffix(d.Hostname, ".")); h != "" {
		names[h] = true
		names[shortName(h)] = true
	}
	addrs := map[string]bool{}
	for _, a := range d.Addrs {
		if ip := parseAddr(a); ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			addrs[ip.String()] = true
		}
	}
	var byAddr string
	for _, s := range infos {
		inst := s.Labels["instance"]
		if inst == "" {
			continue
		}
		node := strings.ToLower(s.Labels["nodename"])
		if node != "" && (names[node] || names[shortName(node)]) {
			return inst, nil
		}
		host := strings.ToLower(instanceHost(inst))
		if byAddr == "" && (names[host] || names[shortName(host)] || addrs[canonicalIP(host)]) {
			byAddr = inst
		}
	}
	if byAddr != "" {
		return byAddr, nil
	}
	return "", ErrNoTarget
}

func shortName(h string) string {
	if net.ParseIP(h) != nil {
		return h
	}
	short, _, _ := strings.Cut(h, ".")
	return short
}

// instanceHost strips the port from an instance label ("10.0.0.5:9100").
func instanceHost(inst string) string {
	if h, _, err := net.SplitHostPort(inst); err == nil {
		return h
	}
	return strings.Trim(inst, "[]")
}

func parseAddr(a string) net.IP {
	a, _, _ = strings.Cut(a, "/")
	return net.ParseIP(a)
}

func canonicalIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}

// Chart is one named series for a device chart.
type Chart struct {
	Key     string // stable id: cpu, memory, disk
	Name    string
	Unit    string // percent
	Samples []Sample
}

// chartQueries are the node-exporter series device charts show. %[1]s is the
// quoted instance and %[2]s the rate window.
var chartQueries = []struct {
	key, name, unit, query string
}{
	{
		"cpu", "CPU", "percent",
		`100 * (1 - avg(rate(node_cpu_seconds_total{instance=%[1]s,mode="idle"}[%[2]s])))`,
	},
	{
		"memory", "Memory", "percent",
		`100 * (1 - node_memory_MemAvailable_bytes{instance=%[1]s} / node_memory_MemTotal_bytes{instance=%[1]s})`,
	},
	{
		"disk", "Disk /", "percent",
		`100 * (1 - node_filesystem_avail_bytes{instance=%[1]s,mountpoint="/"} / node_filesystem_size_bytes{instance=%[1]s,mountpoint="/"})`,
	},
}

// minRateWindow covers at least a few scrapes at the default 15-30 s interval.
const minRateWindow = 2 * time.Minute

// Charts reads the chart series of the node-exporter target instance over the
// from start to end, sampled every step. A chart whose query has no data (a
// metric the exporter does not expose on that OS) has no samples.
func (r *Reader) Charts(ctx context.Context, instance string, start, end time.Time, step time.Duration) ([]Chart, error) {
	rateWindow := max(step, minRateWindow)
	inst := strconv.Quote(instance)
	out := make([]Chart, 0, len(chartQueries))
	for _, cq := range chartQueries {
		q := fmt.Sprintf(cq.query, inst, promDuration(rateWindow))
		series, err := r.q.QueryRange(ctx, q, start, end, step)
		if err != nil {
			return nil, fmt.Errorf("chart %s: %w", cq.key, err)
		}
		c := Chart{Key: cq.key, Name: cq.name, Unit: cq.unit, Samples: []Sample{}}
		if len(series) > 0 {
			for _, s := range series[0].Samples {
				if !math.IsNaN(s.V) && !math.IsInf(s.V, 0) {
					c.Samples = append(c.Samples, s)
				}
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// promDuration formats d in whole seconds, as PromQL range selectors take.
func promDuration(d time.Duration) string {
	return strconv.FormatInt(int64(d/time.Second), 10) + "s"
}
