import { useDeviceMetrics } from '../api/hooks.ts';
import type { MetricChart, MetricsStatus } from '../api/client.ts';

const emptyText: Record<Exclude<MetricsStatus, 'ok'>, string> = {
  not_configured: 'No Prometheus configured. Start the hub with --prometheus-url to chart node-exporter data.',
  no_target: 'Prometheus has no node-exporter target for this device.',
  unreachable: 'Prometheus is unreachable right now.',
};

/** Charts of a device's Prometheus (node-exporter) series, or why there are none. */
export function DeviceCharts({ deviceId }: { deviceId: string }) {
  const { data, isPending, isError } = useDeviceMetrics(deviceId);
  if (isPending) {
    return <p className="muted small">Loading…</p>;
  }
  if (isError) {
    return <p className="muted small">Metrics are unavailable.</p>;
  }
  if (data.status !== 'ok') {
    return (
      <p className="muted small" title={data.message}>
        {emptyText[data.status]}
      </p>
    );
  }
  return (
    <>
      {data.charts.map((c) => (
        <Chart key={c.key} chart={c} start={data.start ?? 0} end={data.end ?? 0} />
      ))}
      <p className="muted small">
        From Prometheus · last hour · <span className="mono">{data.instance}</span>
      </p>
    </>
  );
}

const W = 300;
const H = 48;

/** One chart, its x axis spanning start..end (unix ms) so recent data sits at the right. */
function Chart({ chart, start, end }: { chart: MetricChart; start: number; end: number }) {
  const pts = chart.points;
  const first = pts.at(0);
  const last = pts.at(-1);
  const label = last === undefined ? '—' : formatValue(last[1], chart.unit);
  let line = '';
  let area = '';
  if (first && last && pts.length > 1) {
    const span = end - start || 1;
    const x = (t: number) => (((t - start) / span) * W).toFixed(1);
    const top = chart.unit === 'percent' ? 100 : Math.max(...pts.map((p) => p[1])) || 1;
    line = pts.map(([t, v]) => `${x(t)},${(H - Math.min(v / top, 1) * H).toFixed(1)}`).join(' ');
    area = `${x(first[0])},${String(H)} ${line} ${x(last[0])},${String(H)}`;
  }
  return (
    <div className="metric-chart">
      <div className="kv">
        <span className="muted">{chart.name}</span>
        <span className="num">{label}</span>
      </div>
      {line ? (
        <svg viewBox={`0 0 ${String(W)} ${String(H)}`} preserveAspectRatio="none" role="img" aria-label={`${chart.name}: ${label}`}>
          <polygon points={area} className="metric-area" />
          <polyline points={line} className="metric-line" />
        </svg>
      ) : (
        <p className="muted small">No data.</p>
      )}
    </div>
  );
}

function formatValue(v: number, unit: string): string {
  return unit === 'percent' ? `${v.toFixed(1)}%` : v.toPrecision(3);
}
