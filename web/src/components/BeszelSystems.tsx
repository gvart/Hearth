import type { BeszelSystem, BeszelSystemStatus } from '../api/client.ts';
import { useBeszelSystems } from '../api/hooks.ts';
import { relativeTime } from '../format.ts';

const statusLabels: Record<BeszelSystemStatus, string> = {
  up: 'Up',
  down: 'Down',
  paused: 'Paused',
  pending: 'Pending',
};

function statusDot(s: BeszelSystemStatus) {
  if (s === 'up') {
    return 'dot dot-online';
  }
  return s === 'down' ? 'dot dot-offline' : 'dot dot-unknown';
}

/** "3d 4h", "4h 12m", "12m": how long a system has been up. */
function uptimeLabel(s: BeszelSystem) {
  if (s.status !== 'up' || s.uptime <= 0) {
    return '—';
  }
  const [days, hours, mins] = [Math.floor(s.uptime / 86_400), Math.floor(s.uptime / 3_600) % 24, Math.floor(s.uptime / 60) % 60];
  if (days > 0) {
    return `${String(days)}d ${String(hours)}h`;
  }
  return hours > 0 ? `${String(hours)}h ${String(mins)}m` : `${String(mins)}m`;
}

function pct(s: BeszelSystem, v: number) {
  return s.status === 'up' ? `${v.toFixed(0)}%` : '—';
}

/**
 * The systems a Beszel hub monitors, as the hub last read them, each linked
 * to the Hearth device or network host it is. Renders nothing when no Beszel
 * is configured.
 */
export function BeszelSystems({ now, onSelect }: { now: number; onSelect: (deviceId: string) => void }) {
  const q = useBeszelSystems();
  const data = q.data;
  if (!data || data.status === 'not_configured') {
    return null;
  }
  const up = data.systems.filter((s) => s.status === 'up').length;
  return (
    <section className="unmanaged" aria-labelledby="beszel-title">
      <div className="section-head">
        <h2 id="beszel-title">From Beszel</h2>
        <p className="muted">
          {data.status === 'connecting'
            ? 'Reading Beszel…'
            : `${String(up)} of ${String(data.systems.length)} up${data.read_at ? `, read ${relativeTime(data.read_at, now)}` : ''}`}
        </p>
      </div>
      {data.status === 'unavailable' ? (
        <div className="error-box" role="alert">
          Could not read Beszel: {data.error ?? 'unknown error'}
          {data.systems.length > 0 ? '. Showing the last read.' : ''}
        </div>
      ) : null}
      {data.systems.length > 0 ? (
        <div className="table-wrap">
          <table className="devices network beszel">
            <thead>
              <tr>
                <th>Name</th>
                <th>Host</th>
                <th>CPU</th>
                <th>Memory</th>
                <th>Disk</th>
                <th>Uptime</th>
                <th>In Hearth</th>
              </tr>
            </thead>
            <tbody>
              {data.systems.map((s) => (
                <tr key={s.id} aria-label={`${s.name}, ${statusLabels[s.status]}`}>
                  <td>
                    <span className="name-cell">
                      <span className={statusDot(s.status)} role="img" aria-label={statusLabels[s.status]} title={statusLabels[s.status]} />
                      <span className="name">{s.name}</span>
                      {s.status !== 'up' ? <span className="badge badge-quiet">{statusLabels[s.status]}</span> : null}
                    </span>
                  </td>
                  <td className="mono">{s.host}</td>
                  <td>{pct(s, s.cpu)}</td>
                  <td>{pct(s, s.memory)}</td>
                  <td>{pct(s, s.disk)}</td>
                  <td className="muted">{uptimeLabel(s)}</td>
                  <td>
                    {s.device_id ? (
                      <button
                        className="btn btn-ghost btn-small"
                        type="button"
                        title="Open the device"
                        onClick={() => {
                          onSelect(s.device_id);
                        }}
                      >
                        {s.device_name || s.device_id}
                      </button>
                    ) : s.network_mac ? (
                      <span className="muted" title={s.network_mac}>
                        On your network
                      </span>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : data.status === 'ok' ? (
        <p className="muted">Beszel monitors no systems this user can see.</p>
      ) : null}
    </section>
  );
}
