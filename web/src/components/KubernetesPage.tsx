import { useEffect, useState } from 'react';
import type { KubeCluster, KubePod, KubeSnapshot, KubeState } from '../api/client.ts';
import { useDevices, useKubeCluster, useKubeClusters, useRemoveKubeCluster } from '../api/hooks.ts';
import { displayName, relativeTime } from '../format.ts';
import { AddClusterDialog } from './AddClusterDialog.tsx';
import { DeviceDrawer } from './DeviceDrawer.tsx';
import { PodLogsDialog } from './PodLogsDialog.tsx';

type Tab = 'pods' | 'nodes' | 'workloads' | 'events';
const tabs: { id: Tab; label: string }[] = [
  { id: 'pods', label: 'Pods' },
  { id: 'nodes', label: 'Nodes' },
  { id: 'workloads', label: 'Workloads' },
  { id: 'events', label: 'Events' },
];

const stateLabel: Record<KubeState, string> = { connecting: 'Connecting', connected: 'Connected', error: 'Unreachable' };
const stateDot: Record<KubeState, string> = { connecting: 'dot-unknown', connected: 'dot-online', error: 'dot-error' };

function StateDot({ state }: { state: KubeState }) {
  return <span className={`dot ${stateDot[state]}`} role="img" aria-label={stateLabel[state]} title={stateLabel[state]} />;
}

/** Statuses a pod passes through on its way to running. */
const transient = new Set(['Pending', 'ContainerCreating', 'PodInitializing', 'Terminating']);

/** How healthy a pod status reads: ok, on its way (warn) or failing (bad). */
function podTone(p: KubePod): 'ok' | 'warn' | 'bad' {
  if (p.status === 'Completed' || p.status === 'Succeeded') {
    return 'ok';
  }
  if (p.status === 'Running') {
    const [ready, total] = p.ready.split('/');
    return ready === total ? 'ok' : 'warn';
  }
  if (transient.has(p.status) || /^Init:\d+\/\d+$/.test(p.status)) {
    return 'warn';
  }
  return 'bad';
}

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

export function KubernetesPage() {
  const clusters = useKubeClusters();
  const [selectedId, setSelectedId] = useState<string>();
  const [adding, setAdding] = useState(false);

  const list = clusters.data ?? [];
  const selected = list.find((c) => c.id === selectedId) ?? list[0];

  return (
    <main className="content">
      <div className="page-head">
        <div>
          <h1>Kubernetes</h1>
          {clusters.data ? (
            <p className="muted">
              {list.length === 0
                ? 'No clusters yet'
                : `${String(list.length)} cluster${list.length === 1 ? '' : 's'}, read-only`}
            </p>
          ) : null}
        </div>
        <button
          className="btn btn-primary"
          type="button"
          onClick={() => {
            setAdding(true);
          }}
        >
          <span aria-hidden="true">＋</span> Add cluster
        </button>
      </div>

      {clusters.isError ? (
        <div className="error-box" role="alert">
          Could not load clusters: {clusters.error.message}
        </div>
      ) : clusters.isPending ? (
        <p className="muted">Loading clusters…</p>
      ) : list.length === 0 ? (
        <div className="empty">
          <h2>Adopt a cluster</h2>
          <p className="muted">
            Paste a kubeconfig from Talos, k3s or kind. Hearth only reads: nodes, workloads, pods, events and logs. Nothing
            is installed in the cluster.
          </p>
          <button
            className="btn btn-primary"
            type="button"
            onClick={() => {
              setAdding(true);
            }}
          >
            Add cluster
          </button>
        </div>
      ) : (
        <>
          {list.length > 1 ? (
            <div className="segmented" role="tablist" aria-label="Clusters">
              {list.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  role="tab"
                  aria-selected={c.id === selected?.id}
                  className="segment"
                  onClick={() => {
                    setSelectedId(c.id);
                  }}
                >
                  <StateDot state={c.state} />
                  {c.name}
                </button>
              ))}
            </div>
          ) : null}
          {selected ? <ClusterView key={selected.id} cluster={selected} /> : null}
        </>
      )}

      {adding ? (
        <AddClusterDialog
          onClose={() => {
            setAdding(false);
          }}
          onAdded={(c) => {
            setAdding(false);
            setSelectedId(c.id);
          }}
        />
      ) : null}
    </main>
  );
}

function ClusterView({ cluster }: { cluster: KubeCluster }) {
  const snap = useKubeCluster(cluster.id);
  const remove = useRemoveKubeCluster();
  const [tab, setTab] = useState<Tab>('pods');
  const [namespace, setNamespace] = useState('');
  const [logsOf, setLogsOf] = useState<KubePod>();
  const data = snap.data;

  return (
    <section className="cluster" aria-labelledby="cluster-title">
      <div className="cluster-head">
        <div>
          <h2 id="cluster-title" className="status-line">
            <StateDot state={cluster.state} />
            {cluster.name}
          </h2>
          <p className="muted small mono">{cluster.server}</p>
          {data ? (
            <p className="muted small">
              {stateLabel[cluster.state]} · {data.nodes.length} node{data.nodes.length === 1 ? '' : 's'} ·{' '}
              {data.pods.length} pod{data.pods.length === 1 ? '' : 's'}
            </p>
          ) : null}
        </div>
        <button
          className="btn btn-ghost btn-small"
          type="button"
          disabled={remove.isPending}
          onClick={() => {
            if (window.confirm(`Stop watching ${cluster.name} and forget its kubeconfig? The cluster itself is not touched.`)) {
              remove.mutate(cluster.id);
            }
          }}
        >
          Remove
        </button>
      </div>
      {cluster.state === 'error' && cluster.error ? (
        <div className="error-box" role="alert">
          Cannot reach the cluster: {cluster.error}
        </div>
      ) : null}
      {remove.isError ? (
        <div className="error-box" role="alert">
          Could not remove: {remove.error.message}
        </div>
      ) : null}

      <div className="tabs-row">
        <div className="tabs" role="tablist" aria-label="Cluster view">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              className="tab"
              aria-selected={tab === t.id}
              onClick={() => {
                setTab(t.id);
              }}
            >
              {t.label}
            </button>
          ))}
        </div>
        {data && tab !== 'nodes' ? (
          <label className="ns-filter">
            <span className="muted small">Namespace</span>
            <select
              value={namespace}
              onChange={(e) => {
                setNamespace(e.target.value);
              }}
            >
              <option value="">All</option>
              {data.namespaces.map((n) => (
                <option key={n.name} value={n.name}>
                  {n.name}
                </option>
              ))}
            </select>
          </label>
        ) : null}
      </div>

      {snap.isError ? (
        <div className="error-box" role="alert">
          Could not load the cluster: {snap.error.message}
        </div>
      ) : !data ? (
        <p className="muted">Loading…</p>
      ) : cluster.state === 'connecting' && data.pods.length === 0 ? (
        <p className="muted">Connecting to the cluster…</p>
      ) : (
        <ClusterTab tab={tab} data={data} namespace={namespace} onLogs={setLogsOf} />
      )}

      {logsOf ? (
        <PodLogsDialog
          cluster={cluster}
          pod={logsOf}
          onClose={() => {
            setLogsOf(undefined);
          }}
        />
      ) : null}
    </section>
  );
}

interface TabProps {
  tab: Tab;
  data: KubeSnapshot;
  namespace: string;
  onLogs: (p: KubePod) => void;
}

function ClusterTab({ tab, data, namespace, onLogs }: TabProps) {
  const now = useNow(10_000);
  const devices = useDevices();
  const [deviceId, setDeviceId] = useState<string>();
  const inNs = <T extends { namespace: string }>(xs: T[]) => (namespace ? xs.filter((x) => x.namespace === namespace) : xs);
  const device = devices.data?.find((d) => d.id === deviceId);

  switch (tab) {
    case 'pods': {
      const pods = inNs(data.pods);
      return pods.length === 0 ? (
        <p className="muted">No pods.</p>
      ) : (
        <div className="table-wrap">
          <table className="devices kube">
            <thead>
              <tr>
                <th>Pod</th>
                <th>Status</th>
                <th>Ready</th>
                <th>Restarts</th>
                <th>Node</th>
                <th>Age</th>
              </tr>
            </thead>
            <tbody>
              {pods.map((p) => (
                <tr
                  key={`${p.namespace}/${p.name}`}
                  tabIndex={0}
                  aria-label={`${p.namespace}/${p.name}, ${p.status}. Show logs`}
                  onClick={() => {
                    onLogs(p);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onLogs(p);
                    }
                  }}
                >
                  <td>
                    <span className="name">{p.name}</span>
                    <span className="muted small block">{p.namespace}</span>
                  </td>
                  <td>
                    <span className={`pill pill-${podTone(p)}`}>{p.status}</span>
                  </td>
                  <td className="mono">{p.ready}</td>
                  <td className="mono">{p.restarts}</td>
                  <td className="muted">{p.node || '—'}</td>
                  <td className="muted">{relativeTime(p.created, now)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    }
    case 'nodes':
      return (
        <>
          <div className="table-wrap">
            <table className="devices kube">
              <thead>
                <tr>
                  <th>Node</th>
                  <th>Roles</th>
                  <th>Version</th>
                  <th>Addresses</th>
                  <th>Device</th>
                </tr>
              </thead>
              <tbody>
                {data.nodes.map((n) => {
                  const d = devices.data?.find((x) => x.id === n.device_id);
                  return (
                    <tr key={n.name} className="static">
                      <td>
                        <span className="name-cell">
                          <span
                            className={`dot ${n.ready ? 'dot-online' : 'dot-error'}`}
                            role="img"
                            aria-label={n.ready ? 'Ready' : 'Not ready'}
                            title={n.ready ? 'Ready' : 'Not ready'}
                          />
                          <span className="name">{n.name}</span>
                          {n.unschedulable ? <span className="badge">Cordoned</span> : null}
                        </span>
                        <span className="muted small block">
                          {[n.arch, n.cpu && `${n.cpu} CPU`, n.memory].filter(Boolean).join(' · ')}
                        </span>
                      </td>
                      <td className="muted">{n.roles.length ? n.roles.join(', ') : 'worker'}</td>
                      <td className="mono">{n.kubelet_version}</td>
                      <td className="mono">{n.addresses.join(', ') || '—'}</td>
                      <td>
                        {d ? (
                          <button
                            type="button"
                            className="link"
                            onClick={() => {
                              setDeviceId(d.id);
                            }}
                          >
                            {displayName(d)}
                          </button>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {device ? (
            <DeviceDrawer
              device={device}
              onClose={() => {
                setDeviceId(undefined);
              }}
            />
          ) : null}
        </>
      );
    case 'workloads': {
      const ws = inNs(data.workloads);
      return ws.length === 0 ? (
        <p className="muted">No workloads.</p>
      ) : (
        <div className="table-wrap">
          <table className="devices kube">
            <thead>
              <tr>
                <th>Workload</th>
                <th>Kind</th>
                <th>Ready</th>
                <th>Age</th>
              </tr>
            </thead>
            <tbody>
              {ws.map((w) => (
                <tr key={`${w.kind}/${w.namespace}/${w.name}`} className="static">
                  <td>
                    <span className="name">{w.name}</span>
                    <span className="muted small block">{w.namespace}</span>
                  </td>
                  <td className="muted">{w.kind}</td>
                  <td>
                    <span className={`pill pill-${w.ready >= w.desired ? 'ok' : 'warn'}`}>
                      {w.ready}/{w.desired}
                    </span>
                  </td>
                  <td className="muted">{relativeTime(w.created, now)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    }
    case 'events': {
      const evs = inNs(data.events);
      return evs.length === 0 ? (
        <p className="muted">No recent events.</p>
      ) : (
        <ul className="events">
          {evs.map((e) => (
            <li key={e.uid} className={e.type === 'Warning' ? 'event-warning' : undefined}>
              <div className="event-head">
                <span className={`pill pill-${e.type === 'Warning' ? 'bad' : 'ok'}`}>{e.reason || e.type}</span>
                <span className="mono small">{e.object}</span>
                <span className="muted small">{e.namespace}</span>
                <span className="muted small event-time">
                  {relativeTime(e.last, now)}
                  {e.count > 1 ? ` · ×${String(e.count)}` : ''}
                </span>
              </div>
              <p className="small">{e.message}</p>
            </li>
          ))}
        </ul>
      );
    }
  }
}
