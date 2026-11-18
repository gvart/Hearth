// SPDX-License-Identifier: AGPL-3.0-only

package prometheus

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
)

// ErrNoData means a query had no value: the series does not exist (yet).
var ErrNoData = errors.New("prometheus has no value for this query")

// Current returns the current value of the chart series key (cpu, memory or
// disk, in percent) of the node-exporter target instance.
func (r *Reader) Current(ctx context.Context, instance, key string) (float64, error) {
	for _, cq := range chartQueries {
		if cq.key != key {
			continue
		}
		q := fmt.Sprintf(cq.query, strconv.Quote(instance), promDuration(minRateWindow))
		vs, err := r.Values(ctx, q)
		if err != nil {
			return 0, fmt.Errorf("%s of %s: %w", key, instance, err)
		}
		if len(vs) == 0 {
			return 0, fmt.Errorf("%s of %s: %w", key, instance, ErrNoData)
		}
		return vs[0], nil
	}
	return 0, fmt.Errorf("unknown metric %q", key)
}

// Values evaluates q now and returns the value of each series, leaving out
// NaN and infinite values.
func (r *Reader) Values(ctx context.Context, q string) ([]float64, error) {
	series, err := r.q.Query(ctx, q, r.now())
	if err != nil {
		return nil, err
	}
	var out []float64
	for _, s := range series {
		for _, smp := range s.Samples {
			if !math.IsNaN(smp.V) && !math.IsInf(smp.V, 0) {
				out = append(out, smp.V)
			}
		}
	}
	return out, nil
}
