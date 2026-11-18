import { useState, type PointerEvent } from 'react';
import { useDeviceMetrics } from '../api/hooks.ts';
import type { MetricChart, MetricsRange, MetricsStatus } from '../api/client.ts';
import { formatMetric, formatMetricShort, plotPosition, plotShapes, yDomain, type MetricPoint } from '../metrics.ts';

const emptyText: Record<Exclude<MetricsStatus, 'ok'>, string> = {
  not_configured: 'No Prometheus configured. Start the hub with --prometheus-url to chart node-exporter data.',
  no_target: 'Prometheus has no node-exporter target for this device.',
  unreachable: 'Prometheus is unreachable right now.',
  no_data: 'No metrics from this device in this range yet.',
};

const ranges: { value: MetricsRange; label: string }[] = [
  { value: '1h', label: '1 h' },
  { value: '24h', label: '24 h' },
  { value: '168h', label: '7 d' },
];

/** Charts of a device's metrics, built-in or from Prometheus (node-exporter), or why there are none. */
export function DeviceCharts({ deviceId }: { deviceId: string }) {
  const [range, setRange] = useState<MetricsRange>('1h');
  const { data, isPending, isError, isPlaceholderData } = useDeviceMetrics(deviceId, range);
  return (
    <>
      <div className="range-picker" role="group" aria-label="Chart range">
        {ranges.map((r) => (
          <button
            key={r.value}
            type="button"
            className="range-option"
            aria-pressed={r.value === range}
            onClick={() => {
              setRange(r.value);
            }}
          >
            {r.label}
          </button>
        ))}
      </div>
      {isPending ? (
        <p className="muted small">Loading…</p>
      ) : isError ? (
        <p className="muted small">Metrics are unavailable.</p>
      ) : data.status !== 'ok' ? (
        <p className="muted small" title={data.message}>
          {emptyText[data.status]}
        </p>
      ) : (
        <div className={isPlaceholderData ? 'metric-charts metric-charts-stale' : 'metric-charts'}>
          {data.charts.map((c) => (
            <Chart key={c.key} chart={c} start={data.start ?? 0} end={data.end ?? 0} />
          ))}
          {data.source === 'prometheus' ? (
            <p className="muted small">
              From Prometheus · <span className="mono">{data.instance}</span>
            </p>
          ) : null}
        </div>
      )}
    </>
  );
}

const W = 300;
const H = 100;

/** Longer ranges than this label their axis with days rather than times. */
const dayAxisMs = 2 * 24 * 60 * 60 * 1000;

function formatTick(t: number, span: number): string {
  const d = new Date(t);
  return span > dayAxisMs
    ? d.toLocaleDateString([], { weekday: 'short', day: 'numeric' })
    : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatInstant(t: number, span: number): string {
  const time = new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return span > dayAxisMs ? `${new Date(t).toLocaleDateString([], { weekday: 'short' })} ${time}` : time;
}

function nearest(points: MetricPoint[], t: number): MetricPoint | undefined {
  let best = points[0];
  for (const p of points) {
    if (best === undefined || Math.abs(p[0] - t) < Math.abs(best[0] - t)) {
      best = p;
    }
  }
  return best;
}

/** One chart, its x axis spanning start..end (unix ms) so recent data sits at the right. */
function Chart({ chart, start, end }: { chart: MetricChart; start: number; end: number }) {
  const [hover, setHover] = useState<MetricPoint>();
  const pts = chart.points;
  const last = pts.at(-1);
  if (last === undefined) {
    return (
      <figure className="metric-chart">
        <figcaption className="metric-head">
          <span className="metric-name">{chart.name}</span>
        </figcaption>
        <p className="muted small">No data.</p>
      </figure>
    );
  }
  const span = end - start;
  const domain = yDomain(pts, chart.unit);
  const shapes = plotShapes(pts, start, end, domain, W, H);
  const values = pts.map((p) => p[1]);
  const avg = values.reduce((a, b) => a + b, 0) / (values.length || 1);
  const label = formatMetric((hover ?? last)[1], chart.unit);
  const at = hover ? plotPosition(hover, start, end, domain) : undefined;

  const onPointerMove = (e: PointerEvent<HTMLDivElement>) => {
    const box = e.currentTarget.getBoundingClientRect();
    setHover(nearest(pts, start + ((e.clientX - box.left) / (box.width || 1)) * span));
  };

  return (
    <figure className="metric-chart">
      <figcaption className="metric-head">
        <span className="metric-name">{chart.name}</span>
        <span className="metric-read">
          <span className="muted small">
            {hover
              ? formatInstant(hover[0], span)
              : `avg ${formatMetric(avg, chart.unit)} · max ${formatMetric(Math.max(...values), chart.unit)}`}
          </span>
          <span className="metric-value">{label}</span>
        </span>
      </figcaption>
      <div className="metric-body">
        <div className="metric-y" aria-hidden="true">
          <span>{formatMetricShort(domain[1], chart.unit)}</span>
          <span>{formatMetricShort((domain[0] + domain[1]) / 2, chart.unit)}</span>
          <span>{formatMetricShort(domain[0], chart.unit)}</span>
        </div>
        <div
          className="metric-plot"
          onPointerMove={onPointerMove}
          onPointerLeave={() => {
            setHover(undefined);
          }}
        >
          <svg viewBox={`0 0 ${String(W)} ${String(H)}`} preserveAspectRatio="none" role="img" aria-label={`${chart.name}: ${label}`}>
            {[0, H / 2, H].map((y) => (
              <line key={y} x1="0" x2={W} y1={y} y2={y} className="metric-grid" />
            ))}
            {shapes.areas.map((a) => (
              <polygon key={a} points={a} className="metric-area" />
            ))}
            {shapes.lines.map((l) => (
              <polyline key={l} points={l} className="metric-line" />
            ))}
            {shapes.dots ? <path d={shapes.dots} className="metric-dots" /> : null}
          </svg>
          {at ? (
            <>
              <span className="metric-cross" style={{ left: `${String(at[0] * 100)}%` }} />
              <span className="metric-marker" style={{ left: `${String(at[0] * 100)}%`, top: `${String(at[1] * 100)}%` }} />
            </>
          ) : null}
        </div>
        <div className="metric-x" aria-hidden="true">
          <span>{formatTick(start, span)}</span>
          <span>{formatTick(start + span / 2, span)}</span>
          <span>now</span>
        </div>
      </div>
    </figure>
  );
}
