// The web terminal: a shell on a device, in its own browser tab. It is
// loaded on demand, so xterm.js stays out of the main bundle. Closing the
// tab closes the WebSocket, and the hub ends the shell.

import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { useEffect, useRef, useState } from 'react';
import { useDevices } from '../api/hooks.ts';
import {
  consumeTerminalLaunch,
  openTerminal,
  terminalHttpsDocs,
  terminalTransportAllowed,
  type TerminalEvent,
} from '../api/terminal.ts';
import { displayName } from '../format.ts';
import { Logo } from './Logo.tsx';
import { token } from '../theme.ts';
import './TerminalPage.css';

type Status =
  | { kind: 'connecting' }
  | { kind: 'pending'; approval: string }
  | { kind: 'open'; shell: string; idle: number }
  | { kind: 'ended'; message: string; error: boolean };

function minutes(seconds: number): string {
  const m = Math.round(seconds / 60);
  return m >= 1 ? `${String(m)} min` : `${String(seconds)} s`;
}

function statusOf(ev: TerminalEvent): Status {
  switch (ev.type) {
    case 'pending':
      return { kind: 'pending', approval: ev.approval };
    case 'started':
      return { kind: 'open', shell: ev.shell, idle: ev.idle_timeout };
    case 'exit':
      return { kind: 'ended', message: `Session ended: ${ev.reason}`, error: false };
    case 'error':
      return {
        kind: 'ended',
        error: true,
        message:
          ev.code === 'forbidden'
            ? `Not allowed: ${ev.reason}`
            : ev.code === 'not_connected'
              ? 'The device’s agent is not connected to this hub.'
              : `Cannot open a terminal: ${ev.reason}`,
      };
    case 'disconnected':
      return { kind: 'ended', message: 'Connection to the hub lost.', error: true };
  }
}

export default function TerminalPage({ deviceId }: { deviceId: string }) {
  const device = useDevices().data?.find((d) => d.id === deviceId);
  const host = useRef<HTMLDivElement>(null);
  const [status, setStatus] = useState<Status>({ kind: 'connecting' });
  const [attempt, setAttempt] = useState(0);
  // Only a click starts a shell: the Terminal button's, or Connect here.
  const [armedFor, setArmedFor] = useState(() => (consumeTerminalLaunch(deviceId) ? deviceId : null));
  const allowed = terminalTransportAllowed();
  const armed = allowed && armedFor === deviceId;
  const name = device ? displayName(device) : deviceId;

  useEffect(() => {
    document.title = `${name} · Terminal · Hearth`;
  }, [name]);

  useEffect(() => {
    const el = host.current;
    if (!el || !armed) {
      return;
    }
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: token('font-mono'),
      theme: {
        background: token('bg'),
        foreground: token('text'),
        cursor: token('accent'),
        selectionBackground: token('border'),
      },
      scrollback: 5000,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(el);
    fit.fit();
    setStatus({ kind: 'connecting' });
    const conn = openTerminal(
      deviceId,
      { rows: term.rows, cols: term.cols },
      (data) => {
        term.write(data);
      },
      (ev) => {
        const s = statusOf(ev);
        setStatus(s);
        if (s.kind === 'open') {
          term.focus();
        } else if (s.kind === 'ended') {
          term.write(`\r\n\x1b[2m[${s.message}]\x1b[0m\r\n`);
        }
      },
    );
    const input = term.onData((d) => {
      conn.send(d);
    });
    const resize = term.onResize((size) => {
      conn.resize(size);
    });
    const observer = new ResizeObserver(() => {
      fit.fit();
    });
    observer.observe(el);
    return () => {
      observer.disconnect();
      input.dispose();
      resize.dispose();
      conn.close();
      term.dispose();
    };
  }, [deviceId, attempt, armed]);

  return (
    <div className="terminal-page">
      <header className="terminal-bar">
        <a className="brand terminal-brand" href="#/" aria-label="Back to devices">
          <Logo size={22} />
        </a>
        <div className="terminal-title">
          <h1>{name}</h1>
          <p className="small" role="status">
            {!allowed ? (
              <span className="danger-text">
                Terminals need HTTPS.{' '}
                <a href={terminalHttpsDocs} target="_blank" rel="noreferrer">
                  Set up HTTPS
                </a>
              </span>
            ) : !armed ? (
              <span className="muted">Not connected. Connecting starts a shell on this device.</span>
            ) : status.kind === 'connecting' ? (
              <span className="muted">Connecting…</span>
            ) : status.kind === 'pending' ? (
              <span className="warn-text">
                Waiting for approval <span className="mono">{status.approval}</span> (see Approvals)
              </span>
            ) : status.kind === 'open' ? (
              <span className="muted">
                <span className="mono">{status.shell}</span> · ends after {minutes(status.idle)} without input
              </span>
            ) : (
              <span className={status.error ? 'danger-text' : 'muted'}>{status.message}</span>
            )}
          </p>
        </div>
        {allowed && !armed ? (
          <button
            className="btn btn-primary"
            type="button"
            onClick={() => {
              setArmedFor(deviceId);
            }}
          >
            Connect
          </button>
        ) : armed && status.kind === 'ended' ? (
          <button
            className="btn btn-primary"
            type="button"
            onClick={() => {
              setAttempt((n) => n + 1);
            }}
          >
            Reconnect
          </button>
        ) : (
          <button
            className="btn"
            type="button"
            onClick={() => {
              window.close();
              // A tab the user opened directly cannot close itself.
              window.location.hash = '#/';
            }}
          >
            Close
          </button>
        )}
      </header>
      <div className="terminal-host" ref={host} />
    </div>
  );
}
