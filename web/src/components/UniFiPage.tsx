import { useState } from 'react';
import { ApiError } from '../api/client.ts';
import {
  useRemoveUniFiController,
  useRestartUniFiAP,
  useUniFiController,
  useUniFiControllers,
  type UniFiController,
  type UniFiDevice,
  type UniFiState,
} from '../api/unifi.ts';
import { platformsHash } from '../platforms.ts';
import { clientLink, healthDetail } from '../unifi.ts';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import './ProxmoxPage.css';

const stateLabel: Record<UniFiState, string> = {
  connecting: 'Connecting',
  connected: 'Connected',
  unavailable: 'Unavailable',
};
const stateDot: Record<UniFiState, string> = {
  connecting: 'dot-unknown',
  connected: 'dot-online',
  unavailable: 'dot-error',
};
const kindLabel: Record<UniFiController['kind'], string> = {
  unifi_os: 'UniFi OS console',
  classic: 'self-hosted controller',
};
const deviceKind: Record<UniFiDevice['kind'], string> = {
  gateway: 'Gateway',
  switch: 'Switch',
  access_point: 'Access point',
  other: 'Device',
};

/** One UniFi controller's site, opened from the Platforms page (#/platforms/unifi/<id>). */
export function UniFiPage({ id }: { id: string }) {
  const controllers = useUniFiControllers();
  const controller = controllers.data?.find((c) => c.id === id);

  return (
    <main className="content">
      <a className="back-link" href={platformsHash}>
        ‹ Platforms
      </a>
      {controller ? (
        <ControllerView key={controller.id} controller={controller} />
      ) : controllers.isError ? (
        <div className="error-box" role="alert">
          Could not load controllers: {controllers.error.message}
        </div>
      ) : controllers.isPending ? (
        <p className="muted">Loading the controller…</p>
      ) : (
        <div className="empty">
          <h2>No such controller</h2>
          <p className="muted">Hearth does not read a UniFi controller with this ID. It may have been removed.</p>
        </div>
      )}
    </main>
  );
}

function backToPlatforms() {
  window.location.hash = platformsHash;
}

function uptime(s: number): string {
  if (s <= 0) {
    return '—';
  }
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  return d > 0 ? `${String(d)} d ${String(h)} h` : `${String(h)} h ${String(Math.floor((s % 3600) / 60))} min`;
}

function ControllerView({ controller }: { controller: UniFiController }) {
  const snap = useUniFiController(controller.id);
  const remove = useRemoveUniFiController();
  const restart = useRestartUniFiAP(controller.id);
  const [removing, setRemoving] = useState(false);
  const [restarting, setRestarting] = useState<UniFiDevice | null>(null);
  const data = snap.data;
  const cancelled = restart.error instanceof ApiError && restart.error.code === 'reauth_cancelled';
  const signIn = controller.auth === 'api_key' ? 'API key' : `local login ${controller.username}`;

  return (
    <section className="cluster" aria-labelledby="unifi-title">
      <div className="page-head">
        <div>
          <h1 id="unifi-title" className="status-line">
            <span
              className={`dot ${stateDot[controller.state]}`}
              role="img"
              aria-label={stateLabel[controller.state]}
              title={stateLabel[controller.state]}
            />
            {controller.name}
          </h1>
          <p className="muted small mono">
            {controller.url} · site {controller.site}
          </p>
          <p className="muted small">
            {stateLabel[controller.state]} · {kindLabel[controller.kind]} · {signIn} ·{' '}
            {controller.tls === 'fingerprint' ? 'pinned certificate' : 'https'}
          </p>
          {controller.state === 'connected' ? (
            <p className="muted small">
              {controller.devices} {controller.devices === 1 ? 'device' : 'devices'} · {controller.clients}{' '}
              {controller.clients === 1 ? 'client' : 'clients'}
            </p>
          ) : null}
        </div>
        <div className="row-end">
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
          title={`Remove ${controller.name}`}
          actionClass="safe"
          confirmLabel="Remove controller"
          pendingLabel="Removing…"
          pending={remove.isPending}
          error={remove.isError ? remove.error.message : undefined}
          onConfirm={() => {
            remove.mutate(controller.id, { onSuccess: backToPlatforms });
          }}
          onClose={() => {
            setRemoving(false);
          }}
        >
          Hearth stops reading the controller and forgets its credentials. The controller itself is not touched.
        </ConfirmDialog>
      ) : null}
      {restarting ? (
        <ConfirmDialog
          title={`Restart ${restarting.name}`}
          actionClass="dangerous"
          confirmLabel="Restart access point"
          pendingLabel="Restarting…"
          pending={restart.isPending}
          asksPassword
          error={restart.isError && !cancelled ? restart.error.message : undefined}
          done={restart.isSuccess ? restart.data.result : undefined}
          onConfirm={() => {
            restart.mutate(restarting.mac);
          }}
          onClose={() => {
            setRestarting(null);
          }}
        >
          Every Wi-Fi client of this access point drops off for a minute or two, until it is back and they reconnect. An
          access point that does not come back leaves its area without Wi-Fi. The restart is audited.
        </ConfirmDialog>
      ) : null}
      {controller.state === 'unavailable' ? (
        <div className="error-box" role="alert">
          Cannot read this controller: {controller.error || 'no answer'}. Hearth keeps trying.
        </div>
      ) : null}
      {data && data.missing.length > 0 ? (
        <div className="muted small" role="note">
          Not read: {data.missing.join('; ')}. See the docs for the role the account needs.
        </div>
      ) : null}

      {snap.isError ? (
        <div className="error-box" role="alert">
          Could not load the controller: {snap.error.message}
        </div>
      ) : !data ? (
        <p className="muted">Loading…</p>
      ) : controller.state === 'connecting' ? (
        <p className="muted">Connecting to the controller…</p>
      ) : controller.state === 'unavailable' ? null : (
        <>
          {data.health.length > 0 ? (
            <>
              <h2>Health</h2>
              <div className="table-wrap">
                <table className="devices kube pve-table">
                  <thead>
                    <tr>
                      <th>Subsystem</th>
                      <th>Status</th>
                      <th className="pve-wide">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.health.map((h) => (
                      <tr key={h.subsystem}>
                        <td className="name mono">{h.subsystem}</td>
                        <td className="muted">{h.status || '—'}</td>
                        <td className="pve-wide muted">{healthDetail(h) || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : null}
          <h2>Devices</h2>
          {data.devices.length === 0 ? (
            <p className="muted">No devices to show.</p>
          ) : (
            <div className="table-wrap">
              <table className="devices kube pve-table">
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>State</th>
                    <th className="pve-wide">Version</th>
                    <th className="pve-wide">Clients</th>
                    <th className="pve-wide">Uptime</th>
                    <th aria-label="Actions" />
                  </tr>
                </thead>
                <tbody>
                  {data.devices.map((d) => (
                    <tr key={d.mac}>
                      <td>
                        <span className="name">{d.name || d.mac}</span>
                        <span className="pve-meta mono">
                          {deviceKind[d.kind]} · {d.model} · {d.ip || d.mac}
                        </span>
                      </td>
                      <td className="muted">{d.state}</td>
                      <td className="pve-wide mono">{d.version || '—'}</td>
                      <td className="pve-wide mono">{String(d.clients)}</td>
                      <td className="pve-wide muted">{uptime(d.uptime)}</td>
                      <td>
                        {d.kind === 'access_point' ? (
                          <button
                            className="btn btn-ghost btn-small"
                            type="button"
                            disabled={restart.isPending}
                            onClick={() => {
                              restart.reset();
                              setRestarting(d);
                            }}
                          >
                            Restart
                          </button>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
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
                    <th className="pve-wide">Connected to</th>
                    <th className="pve-wide">Signal</th>
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
                      <td className="mono">{c.ip || '—'}</td>
                      <td className="pve-wide muted">{clientLink(c)}</td>
                      <td className="pve-wide mono">{!c.wired && c.signal ? `${String(c.signal)} dBm` : '—'}</td>
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
