import { useEffect, useState } from 'react';
import { latest, rememberView, storedView, type DevicesView } from '../devices.ts';
import { deviceHash } from '../nav.ts';
import type { Device } from '../api/client.ts';
import { useDevices, useMetricsSparklines } from '../api/hooks.ts';
import { displayName, formatUptime, osArch, primaryIP, relativeTime, statusLabel } from '../format.ts';
import { AddDeviceDialog } from './AddDeviceDialog.tsx';
import { BeszelSystems } from './BeszelSystems.tsx';
import { TalosNodes } from './TalosNodes.tsx';
import { DeviceSparklines } from './DeviceSparklines.tsx';
import { Meter } from './Meter.tsx';
import { PluginDevices } from './PluginDevices.tsx';
import { StatusDot } from './StatusDot.tsx';
import { UnmanagedHosts } from './UnmanagedHosts.tsx';
import './DevicesPage.css';

const statusOrder = { online: 0, unknown: 1, offline: 2 } as const;

function byStatusThenName(a: Device, b: Device) {
  return statusOrder[a.status] - statusOrder[b.status] || displayName(a).localeCompare(displayName(b));
}

/** One fact of a device block: a label, a dotted leader and the value. */
function Pin({ label, value }: { label: string; value: string }) {
  return (
    <span className="pin">
      <span className="pin-label">{label}</span>
      <span className="pin-lead" aria-hidden="true" />
      <span className="pin-value">{value}</span>
    </span>
  );
}

/** Opens a device's page. */
function open(id: string) {
  window.location.hash = deviceHash(id);
}

/** The current time, re-read every interval so relative times stay fresh. */
function useNow(intervalMs: number) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => {
      setNow(Date.now());
    }, intervalMs);
    return () => {
      clearInterval(t);
    };
  }, [intervalMs]);
  return now;
}

export function DevicesPage() {
  const devices = useDevices();
  const sparklines = useMetricsSparklines();
  const now = useNow(1_000); // uptime ticks in seconds
  const [adding, setAdding] = useState(false);
  const [view, setView] = useState<DevicesView>(storedView);
  // Device IDs present when "Add device" was last opened; rows not in it are new.
  const [baseline, setBaseline] = useState<Set<string>>();

  const list = (devices.data ?? []).slice().sort(byStatusThenName);
  const isNew = (d: Device) => baseline !== undefined && !baseline.has(d.id);
  const joined = adding ? list.find(isNew) : undefined;
  const online = list.filter((d) => d.status === 'online').length;

  const openAdd = () => {
    setBaseline(new Set(list.map((d) => d.id)));
    setAdding(true);
  };

  return (
    <>
      <main className="content">
        <div className="page-head">
          <div>
            <h1>Devices</h1>
            {devices.data ? (
              <p className="muted">
                {list.length === 0
                  ? 'No devices yet'
                  : `${String(online)} of ${String(list.length)} online`}
              </p>
            ) : null}
          </div>
          <div className="devices-tools">
            <div className="range-picker" role="group" aria-label="View">
              {(['blocks', 'table'] as const).map((v) => (
                <button
                  key={v}
                  type="button"
                  className="range-option"
                  aria-pressed={view === v}
                  onClick={() => {
                    rememberView(v);
                    setView(v);
                  }}
                >
                  {v === 'blocks' ? 'Blocks' : 'Table'}
                </button>
              ))}
            </div>
            <button className="btn btn-primary" type="button" onClick={openAdd}>
              <span aria-hidden="true">＋</span> Add device
            </button>
          </div>
        </div>

        {devices.isError ? (
          <div className="error-box" role="alert">
            Could not load devices: {devices.error.message}
          </div>
        ) : devices.isPending ? (
          <p className="muted">Loading devices…</p>
        ) : list.length === 0 ? (
          <div className="empty">
            <h2>Bring your first device home</h2>
            <p className="muted">Add a Raspberry Pi, a NAS, a laptop or a cluster node. It shows up here within seconds.</p>
            <button className="btn btn-primary" type="button" onClick={openAdd}>
              Add device
            </button>
          </div>
        ) : view === 'blocks' ? (
          <div className="dev-block-grid">
            {list.map((d, i) => {
              const charts = sparklines.data?.devices[d.id];
              const on = d.status === 'online';
              return (
                <a
                  key={d.id}
                  href={deviceHash(d.id)}
                  className={on ? 'dev-block' : 'dev-block dev-block-off'}
                  aria-label={`${displayName(d)}, ${statusLabel(d.status)}`}
                >
                  <span className="dev-block-head">
                    <span>D{i + 1}</span>
                    <span className="dev-block-state">
                      <StatusDot status={d.status} />
                      {statusLabel(d.status)}
                    </span>
                  </span>
                  <span className="dev-block-name">
                    {displayName(d)}
                    {isNew(d) ? <span className="badge">New</span> : null}
                  </span>
                  <span className="pins">
                    <Pin label="Addr" value={primaryIP(d) ?? '—'} />
                    <Pin label="OS" value={osArch(d)} />
                    {on ? (
                      <Pin label="Up" value={formatUptime(d, now)} />
                    ) : (
                      <Pin label="Seen" value={d.status === 'unknown' ? '—' : relativeTime(d.last_seen, now)} />
                    )}
                  </span>
                  <Meter label="CPU" percent={on ? latest(charts, 'cpu') : undefined} plain />
                  <Meter label="Mem" percent={on ? latest(charts, 'memory') : undefined} />
                  <Meter label="Disk" percent={on ? latest(charts, 'disk') : undefined} />
                </a>
              );
            })}
          </div>
        ) : (
          <div className="table-wrap">
            <table className="devices">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>OS / arch</th>
                  <th>IP</th>
                  <th>Last seen</th>
                  <th>Uptime</th>
                  <th className="spark-col">Last hour</th>
                </tr>
              </thead>
              <tbody>
                {list.map((d) => (
                  <tr
                    key={d.id}
                    className={isNew(d) ? 'row-new' : undefined}
                    tabIndex={0}
                    aria-label={`${displayName(d)}, ${statusLabel(d.status)}`}
                    onClick={() => {
                      open(d.id);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        open(d.id);
                      }
                    }}
                  >
                    <td>
                      <span className="name-cell">
                        <StatusDot status={d.status} />
                        <span className="name">{displayName(d)}</span>
                        {isNew(d) ? <span className="badge">New</span> : null}
                      </span>
                    </td>
                    <td>{osArch(d)}</td>
                    <td className="mono">{primaryIP(d) ?? '—'}</td>
                    <td className="muted">
                      {d.status === 'online' ? 'now' : d.status === 'unknown' ? '—' : relativeTime(d.last_seen, now)}
                    </td>
                    <td className="muted uptime">{formatUptime(d, now)}</td>
                    <td className="spark-col">
                      <DeviceSparklines
                        charts={sparklines.data?.devices[d.id]}
                        start={sparklines.data?.start ?? 0}
                        end={sparklines.data?.end ?? 0}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <UnmanagedHosts now={now} onAdd={openAdd} />
        <TalosNodes now={now} onSelect={open} />
        <BeszelSystems now={now} onSelect={open} />
        <PluginDevices />
      </main>

      {adding ? (
        <AddDeviceDialog
          joined={joined}
          onClose={() => {
            setAdding(false);
          }}
          onShow={(d) => {
            setAdding(false);
            open(d.id);
          }}
        />
      ) : null}
    </>
  );
}
