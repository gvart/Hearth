import { useState } from 'react';
import type { Device } from '../api/client.ts';
import { DeviceLogsDialog } from './DeviceLogsDialog.tsx';

const managerLabel: Record<string, string> = {
  systemd: 'systemd unit',
  'systemd-user': 'user unit',
  docker: 'container',
};

/** The log sources a device's agent allows, each opening a live log view. */
export function DeviceLogSources({ device }: { device: Device }) {
  const [open, setOpen] = useState<string | null>(null);
  const entries = device.facts.ceiling?.logs ?? [];

  if (entries.length === 0) {
    return (
      <p className="muted small">
        None allowed. Start the agent with <code>--allow-logs systemd:UNIT</code> (or <code>docker:NAME</code>,{' '}
        globs like <code>systemd:*</code>) to stream logs here.
      </p>
    );
  }
  return (
    <>
      <ul className="log-sources">
        {entries.map((e) => (
          <li key={e}>
            <LogSource
              entry={e}
              disabled={device.status !== 'online'}
              onOpen={(source) => {
                setOpen(source);
              }}
            />
          </li>
        ))}
      </ul>
      {open !== null ? (
        <DeviceLogsDialog
          device={device}
          source={open}
          onClose={() => {
            setOpen(null);
          }}
        />
      ) : null}
    </>
  );
}

/** One ceiling entry: an exact name opens at once, a pattern asks for a name. */
function LogSource({ entry, disabled, onOpen }: { entry: string; disabled: boolean; onOpen: (source: string) => void }) {
  const i = entry.indexOf(':');
  const manager = entry.slice(0, i);
  const pattern = entry.slice(i + 1);
  const glob = /[*?[]/.test(pattern);
  const [name, setName] = useState('');

  if (!glob) {
    return (
      <button
        className="btn btn-small log-source"
        type="button"
        disabled={disabled}
        onClick={() => {
          onOpen(entry);
        }}
      >
        <span className="muted small">{managerLabel[manager] ?? manager}</span> <span className="mono">{pattern}</span>
      </button>
    );
  }
  return (
    <form
      className="log-source-form"
      onSubmit={(e) => {
        e.preventDefault();
        if (name.trim()) {
          onOpen(`${manager}:${name.trim()}`);
        }
      }}
    >
      <span className="muted small">{managerLabel[manager] ?? manager}</span>
      <input
        className="mono"
        aria-label={`${managerLabel[manager] ?? manager} name (${pattern})`}
        placeholder={pattern}
        value={name}
        onChange={(e) => {
          setName(e.target.value);
        }}
      />
      <button className="btn btn-small" type="submit" disabled={disabled || !name.trim()}>
        Open
      </button>
    </form>
  );
}
