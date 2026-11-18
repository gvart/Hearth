import type { ReactNode } from 'react';
import type { Device } from '../api/client.ts';
import { displayName, formatBytes, formatDateTime, osArch, primaryIP, statusLabel } from '../format.ts';
import { DeviceCharts } from './DeviceCharts.tsx';
import { Modal } from './Modal.tsx';
import { StatusDot } from './StatusDot.tsx';

export function DeviceDrawer({ device, onClose }: { device: Device; onClose: () => void }) {
  const f = device.facts;
  const labels = Object.entries(device.labels);
  const disks = f.disks ?? [];
  const ifaces = f.interfaces ?? [];
  const caps = f.capabilities ?? [];

  return (
    <Modal className="drawer" labelledBy="drawer-title" onClose={onClose}>
      <header className="drawer-head">
        <div>
          <h2 id="drawer-title">{displayName(device)}</h2>
          <p className="muted status-line">
            <StatusDot status={device.status} /> {statusLabel(device.status)}
            {primaryIP(device) ? <span className="mono"> · {primaryIP(device)}</span> : null}
          </p>
        </div>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>

      <Section title="Device">
        <Row k="ID" v={<span className="mono">{device.id}</span>} />
        <Row k="Hostname" v={f.hostname || device.hostname} />
        <Row k="OS / arch" v={osArch(device)} />
        <Row k="Kernel" v={f.kernel} />
        <Row k="Agent" v={f.agent_version} />
        <Row k="First seen" v={formatDateTime(device.first_seen)} />
        <Row k="Last seen" v={formatDateTime(device.last_seen)} />
        <Row k="Booted" v={formatDateTime(device.boot_time)} />
        <Row
          k="Labels"
          v={
            labels.length ? (
              <span className="chips">
                {labels.map(([k, v]) => (
                  <span className="chip" key={k}>
                    {k}={v}
                  </span>
                ))}
              </span>
            ) : undefined
          }
        />
      </Section>

      <Section title="Metrics">
        <DeviceCharts deviceId={device.id} />
      </Section>

      <Section title="Hardware">
        <Row k="CPU" v={f.cpu_model} />
        <Row k="Cores" v={f.cpu_cores ? String(f.cpu_cores) : undefined} />
        <Row k="Memory" v={f.mem_total_bytes ? formatBytes(f.mem_total_bytes) : undefined} />
      </Section>

      <Section title={`Disks (${String(disks.length)})`}>
        {disks.length ? (
          <table className="mini">
            <thead>
              <tr>
                <th>Mount</th>
                <th>Device</th>
                <th>FS</th>
                <th className="num">Size</th>
              </tr>
            </thead>
            <tbody>
              {disks.map((d) => (
                <tr key={d.mountpoint + d.device}>
                  <td className="mono">{d.mountpoint}</td>
                  <td className="mono">{d.device}</td>
                  <td>{d.fstype}</td>
                  <td className="num">{formatBytes(d.total_bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted small">Not reported yet.</p>
        )}
      </Section>

      <Section title={`Network (${String(ifaces.length)})`}>
        {ifaces.length ? (
          <table className="mini">
            <thead>
              <tr>
                <th>Interface</th>
                <th>MAC</th>
                <th>Addresses</th>
              </tr>
            </thead>
            <tbody>
              {ifaces.map((i) => (
                <tr key={i.name}>
                  <td className="mono">{i.name}</td>
                  <td className="mono">{i.mac || '—'}</td>
                  <td className="mono">
                    {i.ips.length
                      ? i.ips.map((ip) => (
                          <div key={ip}>{ip}</div>
                        ))
                      : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted small">Not reported yet.</p>
        )}
      </Section>

      <Section title="Capabilities">
        {caps.length ? (
          <span className="chips">
            {caps.map((c) => (
              <span className="chip" key={c}>
                {c}
              </span>
            ))}
          </span>
        ) : (
          <p className="muted small">None reported.</p>
        )}
      </Section>
    </Modal>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="drawer-section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function Row({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="kv">
      <span className="muted">{k}</span>
      <span>{v ?? '—'}</span>
    </div>
  );
}
