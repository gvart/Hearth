import { useState } from 'react';
import type { Device } from '../api/client.ts';
import { useDeviceLogs } from '../api/hooks.ts';
import { displayName } from '../format.ts';
import { LogViewer } from './LogViewer.tsx';
import { Modal } from './Modal.tsx';

const tails = [100, 500];

/** Streams one log source of a device (manager:name) while open. */
export function DeviceLogsDialog({ device, source, onClose }: { device: Device; source: string; onClose: () => void }) {
  const [tail, setTail] = useState(100);
  const [epoch, setEpoch] = useState(0);
  const logs = useDeviceLogs(device.id, source, tail, epoch);

  const status = !logs.open ? (
    'Connecting…'
  ) : logs.ended ? (
    <span className={logs.error ? 'logs-error' : undefined} role={logs.error ? 'alert' : undefined}>
      Stream ended{logs.error ? `: ${logs.error}` : ''}
    </span>
  ) : (
    <span className="logs-live">● Live</span>
  );

  return (
    <Modal className="dialog dialog-wide" labelledBy="device-logs-title" onClose={onClose}>
      <header className="dialog-head">
        <div>
          <h2 id="device-logs-title" className="mono">
            {source}
          </h2>
          <p className="muted small">{displayName(device)}</p>
        </div>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      <LogViewer
        key={`${source}/${String(tail)}/${String(epoch)}`}
        lines={logs.lines}
        total={logs.total}
        live={!logs.ended}
        label={`Logs of ${source}`}
        status={
          <>
            {status}
            {logs.skipped > 0 ? ` · ${String(logs.skipped)} lines dropped (reading too slowly)` : ''}
          </>
        }
        controls={
          <>
            <label className="ns-filter">
              <span className="muted small">Last</span>
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
            {logs.ended ? (
              <button
                className="btn btn-small"
                type="button"
                onClick={() => {
                  setEpoch(epoch + 1);
                }}
              >
                Reopen
              </button>
            ) : null}
          </>
        }
      />
    </Modal>
  );
}
