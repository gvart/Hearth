// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"fmt"

	"github.com/robfig/cron/v3"
)

// scheduleTrigger fires on a cron schedule, in the hub's local time zone
// unless the spec starts with CRON_TZ=<zone>. Runs missed while the hub was
// down or not leading are not made up.
type scheduleTrigger struct {
	spec  string
	sched cron.Schedule
	clock Clock
}

func buildSchedule(p Params, deps TriggerDeps) (Trigger, error) {
	var cfg struct {
		Cron string `yaml:"cron"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	// Five fields (minute hour day-of-month month day-of-week), or a
	// descriptor such as @daily or @every 1h.
	sched, err := cron.ParseStandard(cfg.Cron)
	if err != nil {
		return nil, fmt.Errorf("cron %q: %w", cfg.Cron, err)
	}
	return &scheduleTrigger{spec: cfg.Cron, sched: sched, clock: deps.Clock}, nil
}

func (t *scheduleTrigger) Describe() string {
	return fmt.Sprintf("fires on schedule %q", t.spec)
}

func (t *scheduleTrigger) Sample() map[string]any { return map[string]any{} }

func (t *scheduleTrigger) Watch(ctx context.Context, fire FireFunc) error {
	for {
		now := t.clock.Now()
		next := t.sched.Next(now)
		if next.IsZero() {
			<-ctx.Done() // a schedule that never comes (e.g. 30 February)
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.clock.After(next.Sub(now)):
			fire(map[string]any{})
		}
	}
}
