import { useState } from 'react';
import { maxDockerLogTail, useDockerLogs, type DockerContainer } from '../api/docker.ts';
import { LogViewer } from './LogViewer.tsx';
import { Modal } from './Modal.tsx';

const tails = [50, 100, maxDockerLogTail];

/** The last lines of a container's log: a snapshot, read again on Refresh. */
export function DockerLogsDialog({
  deviceId,
  container,
  onClose,
}: {
  deviceId: string;
  container: DockerContainer;
  onClose: () => void;
}) {
  const [tail, setTail] = useState(100);
  const logs = useDockerLogs(deviceId, container.name, tail);

  return (
    <Modal className="dialog dialog-wide" labelledBy="docker-logs-title" onClose={onClose}>
      <header className="dialog-head">
        <div>
          <h2 id="docker-logs-title">{container.name}</h2>
          <p className="muted small">
            {container.image} · {container.status || container.state}
          </p>
        </div>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      {logs.isError ? (
        <div className="error-box" role="alert">
          Could not read the logs: {logs.error.message}
        </div>
      ) : null}
      <LogViewer
        key={String(tail)}
        lines={logs.data?.lines ?? []}
        live={false}
        label="Container logs"
        status={logs.data === undefined && !logs.isError ? 'Loading…' : `Snapshot of the last ${String(tail)} lines`}
        controls={
          <>
            <label className="ns-filter">
              <span className="muted small">Lines</span>
              <select
                value={tail}
                onChange={(e) => {
                  setTail(Number(e.target.value));
                }}
              >
                {tails.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </label>
            <button
              className="btn btn-small"
              type="button"
              disabled={logs.isFetching}
              onClick={() => {
                void logs.refetch();
              }}
            >
              {logs.isFetching ? 'Loading…' : 'Refresh'}
            </button>
          </>
        }
      />
    </Modal>
  );
}
