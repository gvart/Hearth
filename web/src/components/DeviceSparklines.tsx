import { memo } from 'react';
import type { MetricChart } from '../api/client.ts';
import { formatMetric, formatMetricShort, plotShapes, yDomain } from '../metrics.ts';

/** The metrics of a device list row, in order, with their short captions. */
const slots = [
  { key: 'cpu', caption: 'CPU' },
  { key: 'memory', caption: 'Mem' },
  { key: 'disk', caption: 'Disk' },
  { key: 'temperature', caption: 'Temp' },
  { key: 'net_rx', caption: 'In' },
  { key: 'net_tx', caption: 'Out' },
];

const W = 100;
const H = 100;

/** One small trend per metric over the last hour. Memoized: the device list re-renders every second. */
export const DeviceSparklines = memo(function DeviceSparklines({
  charts,
  start,
  end,
}: {
  charts: MetricChart[] | undefined;
  start: number;
  end: number;
}) {
  if (!charts) {
    return <span className="muted">—</span>;
  }
  return (
    <span className="sparks">
      {slots.map((s) => {
        const chart = charts.find((c) => c.key === s.key);
        const last = chart?.points.at(-1);
        if (!chart || !last) {
          return (
            <span key={s.key} className="spark" data-metric={s.key}>
              <span className="spark-cap">
                <span>{s.caption}</span>
                <span>—</span>
              </span>
            </span>
          );
        }
        const shapes = plotShapes(chart.points, start, end, yDomain(chart.points, chart.unit), W, H);
        return (
          <span key={s.key} className="spark" data-metric={s.key} title={`${chart.name}: ${formatMetric(last[1], chart.unit)}`}>
            <span className="spark-cap">
              <span>{s.caption}</span>
              <span className="spark-value">{formatMetricShort(last[1], chart.unit)}</span>
            </span>
            <svg viewBox={`0 0 ${String(W)} ${String(H)}`} preserveAspectRatio="none" aria-hidden="true">
              {shapes.areas.map((a) => (
                <polygon key={a} points={a} className="metric-area" />
              ))}
              {shapes.lines.map((l) => (
                <polyline key={l} points={l} className="metric-line" />
              ))}
              {shapes.dots ? <path d={shapes.dots} className="metric-dots" /> : null}
            </svg>
          </span>
        );
      })}
    </span>
  );
});
