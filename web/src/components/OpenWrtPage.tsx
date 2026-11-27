import { useState } from 'react';
import { ApiError } from '../api/client.ts';
import {
  useOpenWrtRouter,
  useOpenWrtRouters,
  useRemoveOpenWrtRouter,
  useRestartOpenWrtDNS,
  type OpenWrtRouter,
  type OpenWrtState,
} from '../api/openwrt.ts';
import { formatBytes } from '../format.ts';
import { clientVia, leaseLeft } from '../openwrt.ts';
import { platformsHash } from '../platforms.ts';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import './ProxmoxPage.css';

const stateLabel: Record<OpenWrtState, string> = {
  connecting: 'Connecting',
  connected: 'Connected',
  unavailable: 'Unavailable',
};
const stateDot: Record<OpenWrtState, string> = {
  connecting: 'dot-unknown',
  connected: 'dot-online',
  unavailable: 'dot-error',
};
const tlsLabel: Record<OpenWrtRouter['tls'], string> = {
  none: 'plain http',
  system: 'https',
  fingerprint: 'https, pinned certificate',
};

/** One OpenWrt router, opened from the Platforms page (#/platforms/openwrt/<id>). */
export function OpenWrtPage({ id }: { id: string }) {
  const routers = useOpenWrtRouters();
  const router = routers.data?.find((r) => r.id === id);

  return (
    <main className="content">
      <a className="back-link" href={platformsHash}>
        ‹ Platforms
      </a>
      {router ? (
        <RouterView key={router.id} router={router} />
      ) : routers.isError ? (
        <div className="error-box" role="alert">
          Could not load routers: {routers.error.message}
        </div>
      ) : routers.isPending ? (
        <p className="muted">Loading the router…</p>
      ) : (
        <div className="empty">
          <h2>No such router</h2>
          <p className="muted">Hearth does not read an OpenWrt router with this ID. It may have been removed.</p>
        </div>
      )}
    </main>
  );
}

function backToPlatforms() {
  window.location.hash = platformsHash;
}

function uptime(s: number): string {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  return d > 0 ? `${String(d)} d ${String(h)} h` : `${String(h)} h ${String(Math.floor((s % 3600) / 60))} min`;
}

function RouterView({ router }: { router: OpenWrtRouter }) {
  const snap = useOpenWrtRouter(router.id);
  const remove = useRemoveOpenWrtRouter();
  const restart = useRestartOpenWrtDNS(router.id);
  const [removing, setRemoving] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const data = snap.data;
  const sys = data?.system;
  const cancelled = restart.error instanceof ApiError && restart.error.code === 'reauth_cancelled';

  return (
    <section className="cluster" aria-labelledby="openwrt-router-title">
      <div className="page-head">
        <div>
          <h1 id="openwrt-router-title" className="status-line">
            <span
              className={`dot ${stateDot[router.state]}`}
              role="img"
              aria-label={stateLabel[router.state]}
              title={stateLabel[router.state]}
            />
            {router.name}
          </h1>
          <p className="muted small mono">
            {router.username}@{router.url}
          </p>
          <p className="muted small">
            {stateLabel[router.state]} · {router.clients} {router.clients === 1 ? 'client' : 'clients'} ·{' '}
            {tlsLabel[router.tls]}
          </p>
          {sys && router.state === 'connected' ? (
            <p className="muted small">
              {[sys.model, sys.release, `up ${uptime(sys.uptime)}`, `load ${sys.load[0].toFixed(2)}`]
                .filter((s) => s !== '')
                .join(' · ')}
              {sys.mem_total > 0
                ? ` · ${formatBytes(sys.mem_total - sys.mem_available)} of ${formatBytes(sys.mem_total)} used`
                : ''}
            </p>
          ) : null}
        </div>
        <div className="row-end">
          <button
            className="btn btn-ghost btn-small"
            type="button"
            disabled={router.state !== 'connected' || restart.isPending}
            onClick={() => {
              restart.reset();
              setRestarting(true);
            }}
          >
            Restart dnsmasq
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
          title={`Remove ${router.name}`}
          actionClass="safe"
          confirmLabel="Remove router"
          pendingLabel="Removing…"
          pending={remove.isPending}
          error={remove.isError ? remove.error.message : undefined}
          onConfirm={() => {
            remove.mutate(router.id, { onSuccess: backToPlatforms });
          }}
          onClose={() => {
            setRemoving(false);
          }}
        >
          Hearth stops reading the router and forgets its password. The router itself is not touched.
        </ConfirmDialog>
      ) : null}
      {restarting ? (
        <ConfirmDialog
          title={`Restart dnsmasq on ${router.name}`}
          actionClass="dangerous"
          confirmLabel="Restart dnsmasq"
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
          dnsmasq is the router's DNS and DHCP server: for a moment no device on the network can look up names or renew a
          lease, and a broken configuration keeps it down. The restart is audited.
        </ConfirmDialog>
      ) : null}
      {router.state === 'unavailable' ? (
        <div className="error-box" role="alert">
          Cannot read this router: {router.error || 'no answer'}. Hearth keeps trying.
        </div>
      ) : null}
      {data && data.missing.length > 0 ? (
        <div className="muted small" role="note">
          Not read: {data.missing.join('; ')}. See the docs for the packages and the rpcd ACL Hearth needs.
        </div>
      ) : null}

      {snap.isError ? (
        <div className="error-box" role="alert">
          Could not load the router: {snap.error.message}
        </div>
      ) : !data ? (
        <p className="muted">Loading…</p>
      ) : router.state === 'connecting' ? (
        <p className="muted">Connecting to the router…</p>
      ) : router.state === 'unavailable' ? null : (
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
                    <th className="pve-wide">Seen by</th>
                    <th className="pve-wide">Signal</th>
                    <th className="pve-wide">Lease</th>
                  </tr>
                </thead>
                <tbody>
                  {data.clients.map((c) => (
                    <tr key={c.mac}>
                      <td>
                        <span className="name">{c.hostname || '—'}</span>
                        <span className="pve-meta mono">{c.mac}</span>
                      </td>
                      <td className="mono">{c.ip || '—'}</td>
                      <td className="pve-wide muted">{clientVia(c)}</td>
                      <td className="pve-wide mono">{c.wireless && c.signal ? `${String(c.signal)} dBm` : '—'}</td>
                      <td className="pve-wide muted">{leaseLeft(c)}</td>
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
                    <th>State</th>
                    <th>Received</th>
                    <th>Sent</th>
                    <th className="pve-wide">Errors</th>
                  </tr>
                </thead>
                <tbody>
                  {data.interfaces.map((i) => (
                    <tr key={i.name}>
                      <td>
                        <span className="name mono">{i.name}</span>
                        <span className="pve-meta mono">{i.mac || i.type}</span>
                      </td>
                      <td className="muted">{i.up ? (i.carrier ? 'Up' : 'No link') : 'Down'}</td>
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
