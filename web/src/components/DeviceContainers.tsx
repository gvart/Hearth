import { useState } from 'react';
import type { Device } from '../api/client.ts';
import { useDocker, type DockerActionName, type DockerContainer } from '../api/docker.ts';
import { formatBytes } from '../format.ts';
import { DockerActionDialog } from './DockerActionDialog.tsx';
import { DockerLogsDialog } from './DockerLogsDialog.tsx';
import './DeviceContainers.css';

/** The device's Docker or Podman stacks, containers and images, as its agent reads them now. */
export function DeviceContainers({ device }: { device: Device }) {
  if (!device.facts.ceiling?.docker) {
    return (
      <p className="muted small">
        Not allowed. Start the agent with <code>--allow-docker</code> to list, start, stop and restart its Docker or
        Podman containers here.
      </p>
    );
  }
  if (device.status !== 'online') {
    return <p className="muted small">The device is not online.</p>;
  }
  return <ContainerTables deviceId={device.id} />;
}

type Pending =
  | { kind: 'action'; action: DockerActionName; container: DockerContainer }
  | { kind: 'logs'; container: DockerContainer };

function ContainerTables({ deviceId }: { deviceId: string }) {
  const q = useDocker(deviceId);
  const [pending, setPending] = useState<Pending | null>(null);
  const refresh = (
    <button
      className="btn btn-ghost"
      type="button"
      disabled={q.isFetching}
      onClick={() => {
        void q.refetch();
      }}
    >
      {q.isFetching ? 'Reading…' : 'Refresh'}
    </button>
  );
  if (q.isPending) {
    return <p className="muted small">Asking the agent…</p>;
  }
  if (q.isError) {
    return (
      <div className="containers-head">
        <p className="muted small">Cannot read the containers: {q.error.message}</p>
        {refresh}
      </div>
    );
  }
  const d = q.data;
  const total = d.containers.length + d.stacks.reduce((n, s) => n + s.containers.length, 0);
  const onAction = (action: DockerActionName, container: DockerContainer) => {
    setPending({ kind: 'action', action, container });
  };
  const onLogs = (container: DockerContainer) => {
    setPending({ kind: 'logs', container });
  };
  const close = () => {
    setPending(null);
  };

  return (
    <div className="containers">
      <div className="containers-head">
        <span className="muted small">
          {total === 1 ? '1 container' : `${String(total)} containers`}
          {d.truncated ? ' (more left out)' : ''}
        </span>
        {refresh}
      </div>
      {d.stacks.map((s) => (
        <div key={s.project}>
          <div className="containers-head">
            <h4 className="small">
              {s.project}{' '}
              <span className="muted">
                · stack, {String(s.running)}/{String(s.containers.length)} running
              </span>
            </h4>
          </div>
          <ContainerTable containers={s.containers} onAction={onAction} onLogs={onLogs} />
        </div>
      ))}
      {d.containers.length ? (
        <div>
          {d.stacks.length ? (
            <div className="containers-head">
              <h4 className="small">Other containers</h4>
            </div>
          ) : null}
          <ContainerTable containers={d.containers} onAction={onAction} onLogs={onLogs} />
        </div>
      ) : null}
      {total === 0 ? <p className="muted small">No containers.</p> : null}
      <details className="containers-images">
        <summary className="small">Images ({d.images.length})</summary>
        {d.images.length ? (
          <table className="mini">
            <thead>
              <tr>
                <th>Image</th>
                <th className="num">Size</th>
              </tr>
            </thead>
            <tbody>
              {d.images.map((i) => (
                <tr key={i.id}>
                  <td className="mono">
                    {i.tags.length ? i.tags.join(', ') : <span className="muted">{shortId(i.id)}</span>}
                  </td>
                  <td className="num">{formatBytes(i.size_bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted small">No images.</p>
        )}
      </details>
      {pending?.kind === 'action' ? (
        <DockerActionDialog deviceId={deviceId} container={pending.container} action={pending.action} onClose={close} />
      ) : null}
      {pending?.kind === 'logs' ? (
        <DockerLogsDialog deviceId={deviceId} container={pending.container} onClose={close} />
      ) : null}
    </div>
  );
}

function ContainerTable({
  containers,
  onAction,
  onLogs,
}: {
  containers: DockerContainer[];
  onAction: (action: DockerActionName, c: DockerContainer) => void;
  onLogs: (c: DockerContainer) => void;
}) {
  return (
    <table className="mini containers-table">
      <thead>
        <tr>
          <th>Container</th>
          <th>State</th>
          <th>
            <span className="sr-only">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {containers.map((c) => (
          <tr key={c.id}>
            <td>
              <span className="mono">{c.name}</span>
              <span className="sub">{c.image}</span>
            </td>
            <td>
              <span className={`pill ${statePill(c.state)}`}>{c.state || 'unknown'}</span>
              <span className="sub">{c.status}</span>
            </td>
            <td className="row-actions">
              {c.state === 'running' ? (
                <>
                  <ActionButton
                    label="Stop"
                    name={c.name}
                    onClick={() => {
                      onAction('stop', c);
                    }}
                  />
                  <ActionButton
                    label="Restart"
                    name={c.name}
                    onClick={() => {
                      onAction('restart', c);
                    }}
                  />
                </>
              ) : (
                <ActionButton
                  label="Start"
                  name={c.name}
                  onClick={() => {
                    onAction('start', c);
                  }}
                />
              )}
              <ActionButton
                label="Logs"
                name={c.name}
                onClick={() => {
                  onLogs(c);
                }}
              />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ActionButton({ label, name, onClick }: { label: string; name: string; onClick: () => void }) {
  return (
    <button className="btn btn-small" type="button" aria-label={`${label} ${name}`} onClick={onClick}>
      {label}
    </button>
  );
}

function statePill(state: string): string {
  switch (state) {
    case 'running':
      return 'pill-ok';
    case 'restarting':
    case 'paused':
    case 'created':
      return 'pill-warn';
    case 'dead':
      return 'pill-bad';
    default:
      return 'pill-muted';
  }
}

function shortId(id: string): string {
  return id.replace(/^sha256:/, '').slice(0, 12);
}
