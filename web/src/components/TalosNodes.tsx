import type { TalosNode } from '../api/client.ts';
import { useTalosNodes } from '../api/hooks.ts';
import { relativeTime } from '../format.ts';

function statusOf(n: TalosNode): { dot: string; label: string } {
  if (n.error) {
    return { dot: 'dot dot-offline', label: 'Unreachable' };
  }
  return n.healthy ? { dot: 'dot dot-online', label: 'Healthy' } : { dot: 'dot dot-unknown', label: 'Degraded' };
}

/** "3d 4h", "4h 12m", "12m" since the node booted. */
function uptimeLabel(n: TalosNode, now: number) {
  const boot = Date.parse(n.boot_time);
  if (n.error || !boot || boot <= 0) {
    return '—';
  }
  const s = Math.max(0, Math.floor((now - boot) / 1000));
  const [days, hours, mins] = [Math.floor(s / 86_400), Math.floor(s / 3_600) % 24, Math.floor(s / 60) % 60];
  if (days > 0) {
    return `${String(days)}d ${String(hours)}h`;
  }
  return hours > 0 ? `${String(hours)}h ${String(mins)}m` : `${String(mins)}m`;
}

function memoryLabel(n: TalosNode) {
  if (n.error || n.mem_total <= 0) {
    return '—';
  }
  return `${((100 * (n.mem_total - n.mem_available)) / n.mem_total).toFixed(0)}%`;
}

/** "11/11", with the services that are not healthy in the title. */
function servicesCell(n: TalosNode) {
  const svcs = n.services ?? [];
  if (n.error || svcs.length === 0) {
    return <span className="muted">—</span>;
  }
  const bad = svcs.filter((s) => s.health === 'unhealthy' || (s.state !== 'Running' && s.state !== 'Finished'));
  const title = svcs.map((s) => `${s.id}: ${s.state}${s.health === 'unknown' ? '' : `, ${s.health}`}${s.message ? ` (${s.message})` : ''}`).join('\n');
  return (
    <span title={title}>
      {String(svcs.length - bad.length)}/{String(svcs.length)}
      {bad.length > 0 ? <span className="badge badge-quiet">{bad.map((s) => s.id).join(', ')}</span> : null}
    </span>
  );
}

/**
 * The Talos nodes the hub reads through the Talos API, each linked to the
 * Hearth device it is (the agent of the Hearth DaemonSet on it). Renders
 * nothing when no talosconfig is configured.
 */
export function TalosNodes({ now, onSelect }: { now: number; onSelect: (deviceId: string) => void }) {
  const q = useTalosNodes();
  const data = q.data;
  if (!data || data.status === 'not_configured') {
    return null;
  }
  const healthy = data.nodes.filter((n) => !n.error && n.healthy).length;
  return (
    <section className="unmanaged" aria-labelledby="talos-title">
      <div className="section-head">
        <h2 id="talos-title">From Talos</h2>
        <p className="muted">
          {data.status === 'connecting'
            ? 'Reading the Talos API…'
            : `${String(healthy)} of ${String(data.nodes.length)} healthy${data.read_at ? `, read ${relativeTime(data.read_at, now)}` : ''}`}
        </p>
      </div>
      {data.status === 'unavailable' ? (
        <div className="error-box" role="alert">
          Could not read the Talos API: {data.error ?? 'unknown error'}
          {data.nodes.length > 0 ? '. Showing the last read.' : ''}
        </div>
      ) : null}
      {data.nodes.length > 0 ? (
        <div className="table-wrap">
          <table className="devices network talos">
            <thead>
              <tr>
                <th>Name</th>
                <th>Address</th>
                <th>Talos</th>
                <th>Services</th>
                <th>Memory</th>
                <th>Load</th>
                <th>Uptime</th>
                <th>In Hearth</th>
              </tr>
            </thead>
            <tbody>
              {data.nodes.map((n) => {
                const st = statusOf(n);
                return (
                  <tr key={n.address} aria-label={`${n.hostname || n.address}, ${st.label}`}>
                    <td>
                      <span className="name-cell">
                        <span className={st.dot} role="img" aria-label={st.label} title={n.error ?? st.label} />
                        <span className="name">{n.hostname || n.address}</span>
                        {st.label !== 'Healthy' ? <span className="badge badge-quiet">{st.label}</span> : null}
                      </span>
                    </td>
                    <td className="mono">{n.address}</td>
                    <td className="mono">{n.version || '—'}</td>
                    <td>{servicesCell(n)}</td>
                    <td>{memoryLabel(n)}</td>
                    <td>{n.error ? '—' : n.load1.toFixed(2)}</td>
                    <td className="muted">{uptimeLabel(n, now)}</td>
                    <td>
                      {n.device_id ? (
                        <button
                          className="btn btn-ghost btn-small"
                          type="button"
                          title="Open the device"
                          onClick={() => {
                            onSelect(n.device_id);
                          }}
                        >
                          {n.device_name || n.device_id}
                        </button>
                      ) : (
                        <span className="muted" title="No Hearth agent runs on this node: see the DaemonSet in docs/talos.md">
                          —
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : data.status === 'ok' ? (
        <p className="muted">The talosconfig names no nodes.</p>
      ) : null}
    </section>
  );
}
