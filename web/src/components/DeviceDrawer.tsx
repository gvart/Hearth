import { useState, type ReactNode } from 'react';
import { useRevokeDevice } from '../api/admin.ts';
import type { Device } from '../api/client.ts';
import { markTerminalLaunch, terminalHttpsDocs, terminalTransportAllowed } from '../api/terminal.ts';
import { displayName, formatBytes, formatDateTime, osArch, primaryIP, statusLabel } from '../format.ts';
import { DeviceCharts } from './DeviceCharts.tsx';
import { DeviceContainers } from './DeviceContainers.tsx';
import { DeviceLogSources } from './DeviceLogSources.tsx';
import { DeviceNetEdges } from './DeviceNetEdges.tsx';
import { ConfirmDialog } from './ConfirmDialog.tsx';
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
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <TerminalButton device={device} />
          <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
            ✕
          </button>
        </div>
      </header>
      {device.facts.ceiling?.shell && !terminalTransportAllowed() ? (
        <p className="small muted">
          Terminals need HTTPS, or a browser on the hub itself.{' '}
          <a href={terminalHttpsDocs} target="_blank" rel="noreferrer">
            Set up HTTPS
          </a>
        </p>
      ) : null}

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

      <Section title="Logs">
        <DeviceLogSources device={device} />
      </Section>

      <Section title="Containers">
        <DeviceContainers device={device} />
      </Section>

      <Section title="Neighbors and connections">
        <DeviceNetEdges device={device} />
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

      <Section title="Access">
        <RevokeDevice device={device} />
      </Section>
    </Modal>
  );
}

/** Revokes the device's certificates, as `hearth device revoke` does. */
function RevokeDevice({ device }: { device: Device }) {
  const [open, setOpen] = useState(false);
  const revoke = useRevokeDevice();
  return (
    <>
      <p className="muted small">
        Revoking cuts the device off: its agent is disconnected within 10 seconds and cannot connect again
        until it is enrolled anew.
      </p>
      <div>
        <button
          className="btn btn-danger btn-small"
          type="button"
          onClick={() => {
            revoke.reset();
            setOpen(true);
          }}
        >
          Revoke device
        </button>
      </div>
      {open ? (
        <ConfirmDialog
          title={`Revoke ${displayName(device)}`}
          actionClass="dangerous"
          confirmLabel="Revoke"
          pendingLabel="Revoking…"
          pending={revoke.isPending}
          error={revoke.isError ? revoke.error.message : undefined}
          done={
            revoke.isSuccess ? (
              <>
                Revoked {revoke.data.revoked} certificate{revoke.data.revoked === 1 ? '' : 's'}. The agent is cut
                off within 10 seconds; enroll it again with <code>hearth agent join</code> to bring it back.
              </>
            ) : undefined
          }
          asksPassword
          onConfirm={() => {
            revoke.mutate(device.id);
          }}
          onClose={() => {
            setOpen(false);
          }}
        >
          <p>
            Every certificate of <strong>{displayName(device)}</strong> (<span className="mono">{device.id}</span>) is
            revoked. Its agent stops and does not reconnect. This cannot be undone: the device has to be enrolled
            again.
          </p>
        </ConfirmDialog>
      ) : null}
    </>
  );
}

/** Opens the device's web terminal in a new tab, if its agent allows shells. */
function TerminalButton({ device }: { device: Device }) {
  const why =
    device.status !== 'online'
      ? 'The device is not online'
      : !device.facts.ceiling?.shell
        ? 'Its agent does not allow shells: start it with --allow-shell'
        : !terminalTransportAllowed()
          ? 'Terminals need HTTPS, or a browser on the hub itself'
          : '';
  if (why) {
    return (
      <button className="btn" type="button" disabled title={why}>
        Terminal
      </button>
    );
  }
  return (
    <a
      className="btn"
      style={{ textDecoration: 'none' }}
      href={`#/terminal/${encodeURIComponent(device.id)}`}
      target="_blank"
      rel="noopener"
      onClick={() => {
        markTerminalLaunch(device.id);
      }}
    >
      Terminal
    </a>
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
