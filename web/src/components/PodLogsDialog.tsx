import { useMemo, useState } from 'react';
import type { KubeCluster, KubePod, LogLine } from '../api/client.ts';
import { useKubePodLogs } from '../api/hooks.ts';
import { LogViewer } from './LogViewer.tsx';
import { Modal } from './Modal.tsx';

const tails = [100, 500, 2000];

export function PodLogsDialog({ cluster, pod, onClose }: { cluster: KubeCluster; pod: KubePod; onClose: () => void }) {
  const [container, setContainer] = useState(pod.containers[0] ?? '');
  const [tail, setTail] = useState(500);
  const logs = useKubePodLogs({ cluster: cluster.id, namespace: pod.namespace, pod: pod.name, container, tail });
  // The Kubernetes API answers a snapshot of the last lines, read again on Refresh.
  const lines = useMemo<LogLine[]>(
    () => (logs.data ? logs.data.replace(/\n$/, '').split('\n') : []).map((text) => ({ ts: null, text })),
    [logs.data],
  );

  return (
    <Modal className="dialog dialog-wide" labelledBy="logs-title" onClose={onClose}>
      <header className="dialog-head">
        <div>
          <h2 id="logs-title">{pod.name}</h2>
          <p className="muted small">
            {pod.namespace} · {pod.status} · {pod.node || 'unscheduled'}
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
        key={`${container}/${String(tail)}`}
        lines={lines}
        live={false}
        label="Pod logs"
        status={logs.data === undefined && !logs.isError ? 'Loading…' : 'Snapshot'}
        controls={
          <>
            {pod.containers.length > 1 ? (
              <label className="ns-filter">
                <span className="muted small">Container</span>
                <select
                  value={container}
                  onChange={(e) => {
                    setContainer(e.target.value);
                  }}
                >
                  {pod.containers.map((c) => (
                    <option key={c}>{c}</option>
                  ))}
                </select>
              </label>
            ) : null}
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
