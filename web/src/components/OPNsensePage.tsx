import { useState } from 'react';
import { ApiError } from '../api/client.ts';
import {
  useOPNsenseFirewall,
  useOPNsenseFirewalls,
  useRemoveOPNsenseFirewall,
  useRestartOPNsenseUnbound,
  type OPNsenseFirewall,
  type OPNsenseState,
} from '../api/opnsense.ts';
import { formatBytes } from '../format.ts';
import { clientVia, firmwareLine, leaseLeft } from '../opnsense.ts';
import { platformsHash } from '../platforms.ts';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import './ProxmoxPage.css';

const stateLabel: Record<OPNsenseState, string> = {
  connecting: 'Connecting',
  connected: 'Connected',
  unavailable: 'Unavailable',
};
const stateDot: Record<OPNsenseState, string> = {
  connecting: 'dot-unknown',
  connected: 'dot-online',
  unavailable: 'dot-error',
};
const tlsLabel: Record<OPNsenseFirewall['tls'], string> = {
  system: 'https',
  fingerprint: 'https, pinned certificate',
};

/** One OPNsense firewall, opened from the Platforms page (#/platforms/opnsense/<id>). */
export function OPNsensePage({ id }: { id: string }) {
  const firewalls = useOPNsenseFirewalls();
  const firewall = firewalls.data?.find((f) => f.id === id);

  return (
    <main className="content">
      <a className="back-link" href={platformsHash}>
        ‹ Platforms
      </a>
      {firewall ? (
        <FirewallView key={firewall.id} firewall={firewall} />
      ) : firewalls.isError ? (
        <div className="error-box" role="alert">
          Could not load firewalls: {firewalls.error.message}
        </div>
      ) : firewalls.isPending ? (
        <p className="muted">Loading the firewall…</p>
      ) : (
        <div className="empty">
          <h2>No such firewall</h2>
          <p className="muted">Hearth does not read an OPNsense firewall with this ID. It may have been removed.</p>
        </div>
      )}
    </main>
  );
}

function backToPlatforms() {
  window.location.hash = platformsHash;
}

function FirewallView({ firewall }: { firewall: OPNsenseFirewall }) {
  const snap = useOPNsenseFirewall(firewall.id);
  const remove = useRemoveOPNsenseFirewall();
  const restart = useRestartOPNsenseUnbound(firewall.id);
  const [removing, setRemoving] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const data = snap.data;
  const sys = data?.system;
  const cancelled = restart.error instanceof ApiError && restart.error.code === 'reauth_cancelled';
  // When the snapshot was fetched: what its leases have left is read against it.
  const now = snap.dataUpdatedAt / 1000;
  const firmware = data ? firmwareLine(data.firmware) : '';

  return (
    <section className="cluster" aria-labelledby="opnsense-firewall-title">
      <div className="page-head">
        <div>
          <h1 id="opnsense-firewall-title" className="status-line">
            <span
              className={`dot ${stateDot[firewall.state]}`}
              role="img"
              aria-label={stateLabel[firewall.state]}
              title={stateLabel[firewall.state]}
            />
            {firewall.name}
          </h1>
          <p className="muted small mono">{firewall.url}</p>
          <p className="muted small">
            {stateLabel[firewall.state]} · {firewall.clients} {firewall.clients === 1 ? 'client' : 'clients'} ·{' '}
            {tlsLabel[firewall.tls]}
          </p>
          {sys && firewall.state === 'connected' ? (
            <p className="muted small">
              {[
                sys.hostname,
                firmware || (sys.versions?.[0] ?? ''),
                sys.uptime ? `up ${sys.uptime}` : '',
                sys.load ? `load ${sys.load}` : '',
                sys.mem_total > 0 ? `${formatBytes(sys.mem_used)} of ${formatBytes(sys.mem_total)} used` : '',
              ]
                .filter((s) => s !== '')
                .join(' · ')}
            </p>
          ) : null}
        </div>
        <div className="row-end">
          <button
            className="btn btn-ghost btn-small"
            type="button"
            disabled={firewall.state !== 'connected' || restart.isPending}
            onClick={() => {
              restart.reset();
              setRestarting(true);
            }}
          >
            Restart Unbound
          </button>
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
      </div>
      {removing ? (
        <ConfirmDialog
          title={`Remove ${firewall.name}`}
          actionClass="safe"
          confirmLabel="Remove firewall"
          pendingLabel="Removing…"
          pending={remove.isPending}
          error={remove.isError ? remove.error.message : undefined}
          onConfirm={() => {
            remove.mutate(firewall.id, { onSuccess: backToPlatforms });
          }}
          onClose={() => {
            setRemoving(false);
          }}
        >
          Hearth stops reading the firewall and forgets its API key. The firewall itself is not touched: delete the key
          there too.
        </ConfirmDialog>
      ) : null}
      {restarting ? (
        <ConfirmDialog
          title={`Restart Unbound on ${firewall.name}`}
          actionClass="dangerous"
          confirmLabel="Restart Unbound"
          pendingLabel="Restarting…"
          pending={restart.isPending}
          asksPassword
          error={restart.isError && !cancelled ? restart.error.message : undefined}
          done={restart.isSuccess ? restart.data.result : undefined}
          onConfirm={() => {
            restart.mutate();
          }}
          onClose={() => {
            setRestarting(false);
          }}
        >
          Unbound is the firewall's DNS resolver: for a moment no device on the network can look up names, its cache is
          emptied, and a broken configuration keeps it down. The restart is audited.
        </ConfirmDialog>
      ) : null}
      {firewall.state === 'unavailable' ? (
        <div className="error-box" role="alert">
          Cannot read this firewall: {firewall.error || 'no answer'}. Hearth keeps trying.
        </div>
      ) : null}
      {data && data.missing.length > 0 ? (
        <div className="muted small" role="note">
          Not read: {data.missing.join('; ')}. See the docs for the privileges Hearth's API key needs.
        </div>
      ) : null}

      {snap.isError ? (
        <div className="error-box" role="alert">
          Could not load the firewall: {snap.error.message}
        </div>
      ) : !data ? (
        <p className="muted">Loading…</p>
      ) : firewall.state === 'connecting' ? (
        <p className="muted">Connecting to the firewall…</p>
      ) : firewall.state === 'unavailable' ? null : (
        <>
          <h2>Clients</h2>
          {data.clients.length === 0 ? (
            <p className="muted">No clients to show.</p>
          ) : (
            <div className="table-wrap">
              <table className="devices kube pve-table">
                <thead>
                  <tr>
                    <th>Client</th>
                    <th>IP</th>
                    <th className="pve-wide">Interface</th>
                    <th className="pve-wide">Seen by</th>
                    <th className="pve-wide">Lease</th>
                  </tr>
                </thead>
                <tbody>
                  {data.clients.map((c) => (
                    <tr key={c.mac}>
                      <td>
                        <span className="name">{c.hostname || '—'}</span>
                        <span className="pve-meta mono">
                          {c.mac}
                          {c.vendor ? ` · ${c.vendor}` : ''}
                        </span>
                      </td>
                      <td className="mono">
                        {c.ip || '—'}
                        {c.ipv6.length > 0 ? <span className="pve-meta mono">{c.ipv6.join(', ')}</span> : null}
                      </td>
                      <td className="pve-wide muted">{c.interface || '—'}</td>
                      <td className="pve-wide muted">{clientVia(c)}</td>
                      <td className="pve-wide muted">{leaseLeft(c, now)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <h2>Interfaces</h2>
          {data.interfaces.length === 0 ? (
            <p className="muted">No interfaces to show.</p>
          ) : (
            <div className="table-wrap">
              <table className="devices kube pve-table">
                <thead>
                  <tr>
                    <th>Interface</th>
                    <th>Received</th>
                    <th>Sent</th>
                    <th className="pve-wide">Errors</th>
                  </tr>
                </thead>
                <tbody>
                  {data.interfaces.map((i) => (
                    <tr key={i.name}>
                      <td>
                        <span className="name">{i.description || i.name}</span>
                        <span className="pve-meta mono">
                          {i.name}
                          {i.device ? ` · ${i.device}` : ''}
                        </span>
                      </td>
                      <td className="mono">{formatBytes(i.rx_bytes)}</td>
                      <td className="mono">{formatBytes(i.tx_bytes)}</td>
                      <td className="pve-wide mono">{String(i.rx_errors + i.tx_errors)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  );
}
