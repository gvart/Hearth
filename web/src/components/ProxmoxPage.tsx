import { useState } from 'react';
import {
  useProxmoxServer,
  useProxmoxServers,
  useRemoveProxmoxServer,
  type ProxmoxActionName,
  type ProxmoxGuest,
  type ProxmoxServer,
  type ProxmoxSnapshot,
  type ProxmoxState,
} from '../api/proxmox.ts';
import { formatBytes } from '../format.ts';
import { platformsHash } from '../platforms.ts';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import { ProxmoxActionDialog } from './ProxmoxActionDialog.tsx';
import './ProxmoxPage.css';

type Tab = 'guests' | 'hosts' | 'storage';
const tabs: { id: Tab; label: string }[] = [
  { id: 'guests', label: 'VMs and LXCs' },
  { id: 'hosts', label: 'Hosts' },
  { id: 'storage', label: 'Storage' },
];

const stateLabel: Record<ProxmoxState, string> = {
  connecting: 'Connecting',
  connected: 'Connected',
  unavailable: 'Unavailable',
};
const stateDot: Record<ProxmoxState, string> = {
  connecting: 'dot-unknown',
  connected: 'dot-online',
  unavailable: 'dot-error',
};

const tlsLabel: Record<ProxmoxServer['tls'], string> = {
  system: 'system CAs',
  ca: 'configured CA',
  fingerprint: 'pinned certificate',
};

function StateDot({ state }: { state: ProxmoxState }) {
  return <span className={`dot ${stateDot[state]}`} role="img" aria-label={stateLabel[state]} title={stateLabel[state]} />;
}

/** How a status reads: fine, on its way or failing. */
function tone(status: string): 'ok' | 'muted' | 'warn' | 'bad' {
  switch (status) {
    case 'running':
    case 'online':
    case 'available':
      return 'ok';
    case 'stopped':
      return 'muted';
    case 'paused':
    case 'unknown':
      return 'warn';
  }
  return 'bad';
}

function StatusPill({ status }: { status: string }) {
  return <span className={`pill pill-${tone(status)}`}>{status}</span>;
}

function formatDuration(seconds: number): string {
  if (seconds <= 0) {
    return '—';
  }
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  if (days > 0) {
    return `${String(days)}d ${String(hours)}h`;
  }
  const minutes = Math.floor((seconds % 3_600) / 60);
  return hours > 0 ? `${String(hours)}h ${String(minutes)}m` : `${String(minutes)}m`;
}

function percent(fraction: number): string {
  return `${(fraction * 100).toFixed(fraction < 0.1 ? 1 : 0)}%`;
}

function usage(used: number, total: number): string {
  return total > 0 ? `${formatBytes(used)} / ${formatBytes(total)}` : '—';
}

/** One Proxmox server, opened from the Platforms page (#/platforms/proxmox/<id>). */
export function ProxmoxPage({ id }: { id: string }) {
  const servers = useProxmoxServers();
  const server = servers.data?.find((s) => s.id === id);

  return (
    <main className="content">
      <a className="back-link" href={platformsHash}>
        ‹ Platforms
      </a>
      {server ? (
        <ServerView key={server.id} server={server} />
      ) : servers.isError ? (
        <div className="error-box" role="alert">
          Could not load servers: {servers.error.message}
        </div>
      ) : servers.isPending ? (
        <p className="muted">Loading the server…</p>
      ) : (
        <div className="empty">
          <h2>No such server</h2>
          <p className="muted">Hearth does not read a Proxmox server with this ID. It may have been removed.</p>
        </div>
      )}
    </main>
  );
}

/** Back to the list, once what this page shows is gone. */
function backToPlatforms() {
  window.location.hash = platformsHash;
}

function ServerView({ server }: { server: ProxmoxServer }) {
  const snap = useProxmoxServer(server.id);
  const remove = useRemoveProxmoxServer();
  const [removing, setRemoving] = useState(false);
  const [tab, setTab] = useState<Tab>('guests');
  const [action, setAction] = useState<{ action: ProxmoxActionName; guest: ProxmoxGuest }>();
  const data = snap.data;

  return (
    <section className="cluster" aria-labelledby="pve-server-title">
      <div className="page-head">
        <div>
          <h1 id="pve-server-title" className="status-line">
            <StateDot state={server.state} />
            {server.name}
          </h1>
          <p className="muted small mono">{server.url}</p>
          <p className="muted small">
            {stateLabel[server.state]} · {server.nodes} host{server.nodes === 1 ? '' : 's'} · {server.guests} guest
            {server.guests === 1 ? '' : 's'} · {tlsLabel[server.tls]}
          </p>
        </div>
        <button
          className="btn btn-ghost btn-small"
          type="button"
          disabled={remove.isPending}
          onClick={() => {
            setRemoving(true);
          }}
        >
          Remove
        </button>
      </div>
      {removing ? (
        <ConfirmDialog
          title={`Remove ${server.name}`}
          actionClass="safe"
          confirmLabel="Remove server"
          pendingLabel="Removing…"
          pending={remove.isPending}
          error={remove.isError ? remove.error.message : undefined}
          onConfirm={() => {
            remove.mutate(server.id, { onSuccess: backToPlatforms });
          }}
          onClose={() => {
            setRemoving(false);
          }}
        >
          Hearth stops reading the server and forgets its API token. The server itself is not touched.
        </ConfirmDialog>
      ) : null}
      {server.state === 'unavailable' ? (
        <div className="error-box" role="alert">
          Cannot read this server: {server.error || 'no answer'}. Hearth keeps trying.
        </div>
      ) : null}

      <div className="tabs-row">
        <div className="tabs" role="tablist" aria-label="Server view">
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
      </div>

      {snap.isError ? (
        <div className="error-box" role="alert">
          Could not load the server: {snap.error.message}
        </div>
      ) : !data ? (
        <p className="muted">Loading…</p>
      ) : server.state === 'connecting' ? (
        <p className="muted">Connecting to the server…</p>
      ) : (
        <ServerTab
          tab={tab}
          data={data}
          onAction={(a, guest) => {
            setAction({ action: a, guest });
          }}
        />
      )}

      {action && data ? (
        <ProxmoxActionDialog
          server={server}
          guest={action.guest}
          action={action.action}
          actionClass={data.action_classes[action.action]}
          onClose={() => {
            setAction(undefined);
          }}
        />
      ) : null}
    </section>
  );
}

interface TabProps {
  tab: Tab;
  data: ProxmoxSnapshot;
  onAction: (action: ProxmoxActionName, guest: ProxmoxGuest) => void;
}

function ServerTab({ tab, data, onAction }: TabProps) {
  switch (tab) {
    case 'guests':
      return <GuestsTable guests={data.guests} onAction={onAction} />;
    case 'hosts':
      return data.nodes.length === 0 ? (
        <p className="muted">No hosts to show.</p>
      ) : (
        <div className="table-wrap">
          <table className="devices kube pve-table">
            <thead>
              <tr>
                <th>Host</th>
                <th>Status</th>
                <th className="pve-wide">CPU</th>
                <th>Memory</th>
                <th className="pve-wide">Disk</th>
                <th className="pve-wide">Uptime</th>
              </tr>
            </thead>
            <tbody>
              {data.nodes.map((n) => (
                <tr key={n.name}>
                  <td>
                    <span className="name">{n.name}</span>
                  </td>
                  <td>
                    <StatusPill status={n.status} />
                  </td>
                  <td className="pve-wide">
                    {n.max_cpu > 0 ? `${percent(n.cpu)} of ${String(n.max_cpu)}` : '—'}
                  </td>
                  <td>{usage(n.mem, n.max_mem)}</td>
                  <td className="pve-wide">{usage(n.disk, n.max_disk)}</td>
                  <td className="pve-wide">{formatDuration(n.uptime)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    case 'storage':
      return data.storage.length === 0 ? (
        <p className="muted">No storage to show.</p>
      ) : (
        <div className="table-wrap">
          <table className="devices kube pve-table">
            <thead>
              <tr>
                <th>Storage</th>
                <th>Status</th>
                <th className="pve-wide">Type</th>
                <th className="pve-wide">Content</th>
                <th>Used</th>
              </tr>
            </thead>
            <tbody>
              {data.storage.map((s) => (
                <tr key={`${s.name}@${s.node}`}>
                  <td>
                    <span className="name">{s.name}</span>
                    <span className="pve-meta">
                      {s.node}
                      {s.shared ? ' · shared' : ''}
                    </span>
                  </td>
                  <td>
                    <StatusPill status={s.status} />
                  </td>
                  <td className="pve-wide">{s.type || '—'}</td>
                  <td className="pve-wide">{s.content || '—'}</td>
                  <td>{usage(s.used, s.total)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
  }
}

function GuestsTable({ guests, onAction }: { guests: ProxmoxGuest[]; onAction: TabProps['onAction'] }) {
  if (guests.length === 0) {
    return <p className="muted">No VMs or LXCs to show.</p>;
  }
  return (
    <div className="table-wrap">
      <table className="devices kube pve-table">
        <thead>
          <tr>
            <th>Guest</th>
            <th className="pve-wide">Status</th>
            <th className="pve-wide">CPU</th>
            <th className="pve-wide">Memory</th>
            <th className="pve-wide">Uptime</th>
            <th>
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {guests.map((g) => (
            <tr key={g.vmid}>
              <td>
                <span className="name">{g.name || `Guest ${String(g.vmid)}`}</span>
                <span className="pve-meta">
                  {g.kind === 'qemu' ? 'VM' : 'LXC'} {g.vmid} · {g.node}
                  <span className="pve-inline-status"> · {g.status}</span>
                </span>
              </td>
              <td className="pve-wide">
                <StatusPill status={g.status} />
              </td>
              <td className="pve-wide">{g.status === 'running' ? `${percent(g.cpu)} of ${String(g.max_cpu)}` : '—'}</td>
              <td className="pve-wide">{g.status === 'running' ? usage(g.mem, g.max_mem) : formatBytes(g.max_mem)}</td>
              <td className="pve-wide">{formatDuration(g.uptime)}</td>
              <td className="row-actions">
                {g.status === 'stopped' ? (
                  <GuestButton action="start" label="Start" guest={g} onAction={onAction} />
                ) : null}
                {g.status === 'running' ? (
                  <>
                    <GuestButton action="stop" label="Stop" guest={g} onAction={onAction} />
                    <GuestButton action="reboot" label="Reboot" guest={g} onAction={onAction} />
                  </>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function GuestButton({
  action,
  label,
  guest,
  onAction,
}: {
  action: ProxmoxActionName;
  label: string;
  guest: ProxmoxGuest;
  onAction: TabProps['onAction'];
}) {
  return (
    <button
      type="button"
      className="btn btn-small"
      aria-label={`${label} ${guest.name || String(guest.vmid)}`}
      onClick={() => {
        onAction(action, guest);
      }}
    >
      {label}
    </button>
  );
}
