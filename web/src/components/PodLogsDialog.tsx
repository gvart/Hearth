import { useEffect, useRef, useState } from 'react';
import type { KubeCluster, KubePod } from '../api/client.ts';
import { useKubePodLogs } from '../api/hooks.ts';
import { Modal } from './Modal.tsx';

const tails = [100, 500, 2000];

export function PodLogsDialog({ cluster, pod, onClose }: { cluster: KubeCluster; pod: KubePod; onClose: () => void }) {
  const [container, setContainer] = useState(pod.containers[0] ?? '');
  const [tail, setTail] = useState(500);
  const logs = useKubePodLogs({ cluster: cluster.id, namespace: pod.namespace, pod: pod.name, container, tail });
  const pre = useRef<HTMLPreElement>(null);

  // Show the newest lines first, as a terminal would.
  useEffect(() => {
    if (pre.current) {
      pre.current.scrollTop = pre.current.scrollHeight;
    }
  }, [logs.data]);

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
      <div className="logs-bar">
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
      </div>
      {logs.isError ? (
        <div className="error-box" role="alert">
          Could not read the logs: {logs.error.message}
        </div>
      ) : (
        <pre ref={pre} className="logs" aria-label="Pod logs" tabIndex={0}>
          {logs.data === undefined ? 'Loading…' : logs.data || '(no output)'}
        </pre>
      )}
    </Modal>
  );
}
