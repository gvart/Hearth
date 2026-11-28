import { useEffect, useState, type ReactNode } from 'react';
import { diskUse, latest, notAllowed } from '../devices.ts';
import { Meter } from './Meter.tsx';
import './DevicesPage.css';
import './PanelsPage.css';
import { useRevokeDevice } from '../api/admin.ts';
import type { Device } from '../api/client.ts';
import { useDevices, useMetricsSparklines } from '../api/hooks.ts';
import { markTerminalLaunch, terminalHttpsDocs, terminalTransportAllowed } from '../api/terminal.ts';
import {
  displayName,
  formatBytes,
  formatDateTime,
  formatUptime,
  osArch,
  primaryIP,
  relativeTime,
  statusLabel,
} from '../format.ts';
import { DeviceCapabilities } from './DeviceCapabilities.tsx';
import { DeviceCharts } from './DeviceCharts.tsx';
import { DeviceContainers } from './DeviceContainers.tsx';
import { DevicePlugins } from './DevicePlugins.tsx';
import { DeviceHubSection } from './DeviceHub.tsx';
import { DeviceLogSources } from './DeviceLogSources.tsx';
import { DeviceNetEdges } from './DeviceNetEdges.tsx';
import { DeviceUpgrade } from './DeviceUpgrade.tsx';
import { DeviceExplain } from './DeviceExplain.tsx';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import { StatusDot } from './StatusDot.tsx';

/** The current time, re-read every interval so the uptime ticks. */
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

/**
 * One device on a page of its own (#/devices/<id>): what it is doing now, what
 * it is, and what its agent lets the hub do. A part the agent does not allow is
 * not given a card; the Capabilities card turns each on.
 */
export function DevicePage({ id }: { id: string }) {
  const devices = useDevices();
  const sparklines = useMetricsSparklines();
  const now = useNow(1_000);
  const device = devices.data?.find((d) => d.id === id);

  if (!device) {
    return (
      <main className="content">
        <a className="back-link" href="#/">
          ‹ Devices
        </a>
        {devices.isError ? (
          <div className="error-box" role="alert">
            Could not load devices: {devices.error.message}
          </div>
        ) : devices.isPending ? (
          <p className="muted">Loading the device…</p>
        ) : (
          <div className="empty">
            <h2>No such device</h2>
            <p className="muted">
              No device has the ID <span className="mono">{id}</span>. It may have been removed.
            </p>
          </div>
        )}
      </main>
    );
  }

  const f = device.facts;
  const labels = Object.entries(device.labels);
  const disks = f.disks ?? [];
  const ifaces = f.interfaces ?? [];
  const caps = f.capabilities ?? [];
  const charts = sparklines.data?.devices[device.id];
  const on = device.status === 'online';
  const off = notAllowed(device);

  return (
    <main className="content device-page">
      <a className="back-link" href="#/">
        ‹ Devices
      </a>
      <div className="page-head">
        <div>
          <h1>{displayName(device)}</h1>
          <p className="muted status-line">
            <StatusDot status={device.status} /> {statusLabel(device.status)}
            {primaryIP(device) ? <span className="mono"> · {primaryIP(device)}</span> : null}
          </p>
        </div>
        <TerminalButton device={device} />
      </div>
      {device.facts.ceiling?.shell && !terminalTransportAllowed() ? (
        <p className="small muted">
          Terminals need HTTPS, or a browser on the hub itself.{' '}
          <a href={terminalHttpsDocs} target="_blank" rel="noreferrer">
            Set up HTTPS
          </a>
        </p>
      ) : null}

      <div className="device-grid">
        <DeviceUpgrade device={device} />
        <Section title="Right now">
          <Meter label="CPU" percent={on ? latest(charts, 'cpu') : undefined} plain />
          <Meter label="Mem" percent={on ? latest(charts, 'memory') : undefined} />
          <Meter label="Disk" percent={on ? latest(charts, 'disk') : undefined} />
          <Row k="Uptime" v={on ? formatUptime(device, now) : undefined} />
          <Row k="Last seen" v={on ? 'now' : device.status === 'unknown' ? undefined : relativeTime(device.last_seen, now)} />
        </Section>

        <Section title="Device">
          <Row k="ID" v={<span className="mono">{device.id}</span>} />
          <Row k="Hostname" v={f.hostname || device.hostname} />
          <Row k="OS / arch" v={osArch(device)} />
          <Row k="Kernel" v={f.kernel} />
          <Row k="Agent" v={f.agent_version} />
          <Row k="First seen" v={formatDateTime(device.first_seen)} />
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

        <Section title="Hardware">
          <Row k="CPU" v={f.cpu_model} />
          <Row k="Cores" v={f.cpu_cores ? String(f.cpu_cores) : undefined} />
          <Row k="Memory" v={f.mem_total_bytes ? formatBytes(f.mem_total_bytes) : undefined} />
          <h3 className="card-label">Capabilities</h3>
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

        <Section title={`Disks (${String(disks.length)})`}>
          {disks.length ? (
            <table className="mini">
              <thead>
                <tr>
                  <th>Mount</th>
                  <th>FS</th>
                  <th className="num">Size</th>
                  <th className="disk-use">Used</th>
                </tr>
              </thead>
              <tbody>
                {disks.map((d) => (
                  <tr key={d.mountpoint + d.device}>
                    <td className="mono">
                      {d.mountpoint}
                      <span className="disk-sub">{d.device}</span>
                    </td>
                    <td>{d.fstype}</td>
                    <td className="num">{formatBytes(d.total_bytes)}</td>
                    <td className="disk-use">
                      <Meter label={`${d.mountpoint} used`} percent={diskUse(d)} />
                    </td>
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

        <Section title="Metrics" wide>
          <DeviceCharts deviceId={device.id} />
        </Section>

        {off.logs ? null : (
          <Section title="Logs">
            <DeviceLogSources device={device} />
          </Section>
        )}

        {off.docker ? null : (
          <Section title="Containers" wide>
            <DeviceContainers device={device} />
          </Section>
        )}

        {off.netEdges ? null : (
          <Section title="Neighbors and connections" wide>
            <DeviceNetEdges device={device} />
          </Section>
        )}

        <DeviceExplain device={device} />

        <DevicePlugins device={device} />

        <DeviceCapabilities device={device} />

        <DeviceHubSection device={device} />

        <Section title="Access">
          <RevokeDevice device={device} />
        </Section>
      </div>
    </main>
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
        ? 'The terminal is off: turn it on in Capabilities below'
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

function Section({ title, wide = false, children }: { title: string; wide?: boolean; children: ReactNode }) {
  return (
    <section className={wide ? 'panel-card card-wide' : 'panel-card'}>
      <h2 className="card-label">{title}</h2>
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
