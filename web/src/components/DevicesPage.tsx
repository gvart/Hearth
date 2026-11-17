import { useEffect, useState } from 'react';
import type { Device } from '../api/client.ts';
import { useDeviceEvents, useDevices, useLogout } from '../api/hooks.ts';
import { displayName, osArch, primaryIP, relativeTime, statusLabel } from '../format.ts';
import { AddDeviceDialog } from './AddDeviceDialog.tsx';
import { DeviceDrawer } from './DeviceDrawer.tsx';
import { Logo } from './Logo.tsx';
import { StatusDot } from './StatusDot.tsx';

const statusOrder = { online: 0, unknown: 1, offline: 2 } as const;

function byStatusThenName(a: Device, b: Device) {
  return statusOrder[a.status] - statusOrder[b.status] || displayName(a).localeCompare(displayName(b));
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
  useDeviceEvents();
  const devices = useDevices();
  const logout = useLogout();
  const now = useNow(10_000);
  const [selectedId, setSelectedId] = useState<string>();
  const [adding, setAdding] = useState(false);
  // Device IDs present when "Add device" was last opened; rows not in it are new.
  const [baseline, setBaseline] = useState<Set<string>>();

  const list = (devices.data ?? []).slice().sort(byStatusThenName);
  const isNew = (d: Device) => baseline !== undefined && !baseline.has(d.id);
  const joined = adding ? list.find(isNew) : undefined;
  const selected = list.find((d) => d.id === selectedId);
  const online = list.filter((d) => d.status === 'online').length;

  const openAdd = () => {
    setBaseline(new Set(list.map((d) => d.id)));
    setAdding(true);
  };

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <Logo size={28} />
          <span>Hearth</span>
        </div>
        <button
          className="btn btn-ghost"
          type="button"
          onClick={() => {
            logout.mutate();
          }}
        >
          Sign out
        </button>
      </header>

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
          <button className="btn btn-primary" type="button" onClick={openAdd}>
            <span aria-hidden="true">＋</span> Add device
          </button>
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
        ) : (
          <div className="table-wrap">
            <table className="devices">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>OS / arch</th>
                  <th>IP</th>
                  <th>Last seen</th>
                  <th title="Not reported by agents yet">Uptime</th>
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
                      setSelectedId(d.id);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setSelectedId(d.id);
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
                    <td className="muted">—</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </main>

      {adding ? (
        <AddDeviceDialog
          joined={joined}
          onClose={() => {
            setAdding(false);
          }}
          onShow={(d) => {
            setAdding(false);
            setSelectedId(d.id);
          }}
        />
      ) : null}
      {selected ? (
        <DeviceDrawer
          device={selected}
          onClose={() => {
            setSelectedId(undefined);
          }}
        />
      ) : null}
    </div>
  );
}
