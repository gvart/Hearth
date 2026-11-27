import { useState } from 'react';
import {
  useESPHomeCall,
  useESPHomeDevice,
  useESPHomeDevices,
  useRemoveESPHomeDevice,
  type ESPHomeDevice,
  type ESPHomeEntity,
  type ESPHomeState,
} from '../api/esphome.ts';
import { entityKindLabel, entityStateText } from '../esphome.ts';
import { platformsHash } from '../platforms.ts';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import './ProxmoxPage.css';

const stateLabel: Record<ESPHomeState, string> = {
  connecting: 'Connecting',
  connected: 'Connected',
  unavailable: 'Unavailable',
};
const stateDot: Record<ESPHomeState, string> = {
  connecting: 'dot-unknown',
  connected: 'dot-online',
  unavailable: 'dot-error',
};

/** One ESPHome device, opened from the Platforms page (#/platforms/esphome/<id>). */
export function ESPHomePage({ id }: { id: string }) {
  const devices = useESPHomeDevices();
  const device = devices.data?.find((d) => d.id === id);

  return (
    <main className="content">
      <a className="back-link" href={platformsHash}>
        ‹ Platforms
      </a>
      {device ? (
        <DeviceView key={device.id} device={device} />
      ) : devices.isError ? (
        <div className="error-box" role="alert">
          Could not load devices: {devices.error.message}
        </div>
      ) : devices.isPending ? (
        <p className="muted">Loading the device…</p>
      ) : (
        <div className="empty">
          <h2>No such device</h2>
          <p className="muted">Hearth does not read an ESPHome device with this ID. It may have been removed.</p>
        </div>
      )}
    </main>
  );
}

function backToPlatforms() {
  window.location.hash = platformsHash;
}

function DeviceView({ device }: { device: ESPHomeDevice }) {
  const snap = useESPHomeDevice(device.id);
  const remove = useRemoveESPHomeDevice();
  const call = useESPHomeCall(device.id);
  const [removing, setRemoving] = useState(false);
  const data = snap.data;
  const about = [
    device.friendly_name && device.friendly_name !== device.name ? device.friendly_name : '',
    device.model,
    device.esphome_version ? `ESPHome ${device.esphome_version}` : '',
    device.mac,
  ].filter((s) => s !== '');

  return (
    <section className="cluster" aria-labelledby="esphome-device-title">
      <div className="page-head">
        <div>
          <h1 id="esphome-device-title" className="status-line">
            <span
              className={`dot ${stateDot[device.state]}`}
              role="img"
              aria-label={stateLabel[device.state]}
              title={stateLabel[device.state]}
            />
            {device.name}
          </h1>
          <p className="muted small mono">{device.address}</p>
          <p className="muted small">
            {stateLabel[device.state]} · {device.entities} {device.entities === 1 ? 'entity' : 'entities'} ·{' '}
            {device.encryption === 'noise' ? 'encrypted' : 'not encrypted'} ·{' '}
            {device.control ? 'calls allowed' : 'read-only'}
          </p>
          {about.length > 0 ? <p className="muted small">{about.join(' · ')}</p> : null}
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
          title={`Remove ${device.name}`}
          actionClass="safe"
          confirmLabel="Remove device"
          pendingLabel="Removing…"
          pending={remove.isPending}
          error={remove.isError ? remove.error.message : undefined}
          onConfirm={() => {
            remove.mutate(device.id, { onSuccess: backToPlatforms });
          }}
          onClose={() => {
            setRemoving(false);
          }}
        >
          Hearth disconnects from the device and forgets its encryption key. The device itself is not touched.
        </ConfirmDialog>
      ) : null}
      {device.state === 'unavailable' ? (
        <div className="error-box" role="alert">
          Cannot read this device: {device.error || 'no answer'}. Hearth keeps trying.
        </div>
      ) : null}
      {!device.control ? (
        <p className="muted small">
          Read-only: Hearth shows the states and calls nothing. To turn switches and press buttons from here, remove the
          device and adopt it again with calls allowed.
        </p>
      ) : null}
      {call.isError ? (
        <div className="error-box" role="alert">
          {call.error.message}
        </div>
      ) : null}

      {snap.isError ? (
        <div className="error-box" role="alert">
          Could not load the device: {snap.error.message}
        </div>
      ) : !data ? (
        <p className="muted">Loading…</p>
      ) : device.state === 'connecting' ? (
        <p className="muted">Connecting to the device…</p>
      ) : data.entities.length === 0 ? (
        <p className="muted">No entities to show.</p>
      ) : (
        <div className="table-wrap">
          <table className="devices kube pve-table">
            <thead>
              <tr>
                <th>Entity</th>
                <th className="pve-wide">Kind</th>
                <th>State</th>
                {device.control ? (
                  <th>
                    <span className="sr-only">Calls</span>
                    <span className={`pill pill-${data.call_class === 'safe' ? 'ok' : 'warn'}`} aria-hidden="true">
                      {data.call_class}
                    </span>
                  </th>
                ) : null}
              </tr>
            </thead>
            <tbody>
              {data.entities.map((e) => (
                <tr key={e.key}>
                  <td>
                    <span className="name">{e.name || e.object_id}</span>
                    <span className="pve-meta mono">{e.object_id}</span>
                  </td>
                  <td className="pve-wide muted">{entityKindLabel[e.kind]}</td>
                  <td className="mono">{entityStateText(e)}</td>
                  {device.control ? (
                    <td className="row-end">
                      <EntityCall
                        entity={e}
                        pending={call.isPending}
                        onCall={(action) => {
                          call.mutate({ key: e.key, action });
                        }}
                      />
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function EntityCall({
  entity,
  pending,
  onCall,
}: {
  entity: ESPHomeEntity;
  pending: boolean;
  onCall: (action: 'on' | 'off' | 'press') => void;
}) {
  if (entity.kind === 'button') {
    return (
      <button
        className="btn btn-ghost btn-small"
        type="button"
        disabled={pending}
        onClick={() => {
          onCall('press');
        }}
      >
        Press
      </button>
    );
  }
  if (entity.kind === 'switch') {
    const on = entity.state === true;
    return (
      <button
        className="btn btn-ghost btn-small"
        type="button"
        disabled={pending}
        aria-label={`Turn ${entity.name} ${on ? 'off' : 'on'}`}
        onClick={() => {
          onCall(on ? 'off' : 'on');
        }}
      >
        Turn {on ? 'off' : 'on'}
      </button>
    );
  }
  return null;
}
