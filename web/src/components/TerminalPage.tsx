// The web terminal: a shell on a device, in its own browser tab. It is
// loaded on demand, so xterm.js stays out of the main bundle. Closing the
// tab closes the WebSocket, and the hub ends the shell.

import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { useEffect, useRef, useState } from 'react';
import { useAIConfig, useRecordings } from '../api/ai.ts';
import { useDevices } from '../api/hooks.ts';
import { useForgetReauth, useWithReauth } from '../api/reauth.ts';
import {
  consumeTerminalLaunch,
  openTerminal,
  terminalHttpsDocs,
  terminalTransportAllowed,
  type TerminalEvent,
} from '../api/terminal.ts';
import { displayName } from '../format.ts';
import { Logo } from './Logo.tsx';
import { MakeRunbook } from './RecordingRunbook.tsx';
import { ReauthHost } from './ReauthDialog.tsx';
import { token } from '../theme.ts';
import './TerminalPage.css';
import './RecordingRunbook.css';

type Status =
  | { kind: 'connecting' }
  | { kind: 'pending'; approval: string }
  | { kind: 'open'; shell: string; idle: number }
  | { kind: 'ended'; message: string; error: boolean };

/** A connection the user asked for: each one is a new session. */
interface Session {
  record: boolean;
  n: number;
}

function minutes(seconds: number): string {
  const m = Math.round(seconds / 60);
  return m >= 1 ? `${String(m)} min` : `${String(seconds)} s`;
}

function statusOf(ev: Exclude<TerminalEvent, { type: 'recording_full' }>): Status {
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
          ev.code === 'reauth_required'
            ? 'Recording a session needs your password again: connect again to enter it.'
            : ev.code === 'ai_off'
              ? 'Recording for a runbook needs AI: turn it on in Settings, AI.'
              : ev.code === 'forbidden'
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
  const ai = useAIConfig();
  const withReauth = useWithReauth();
  const forgetReauth = useForgetReauth();
  const host = useRef<HTMLDivElement>(null);
  const [status, setStatus] = useState<Status>({ kind: 'connecting' });
  const [launch] = useState(() => consumeTerminalLaunch(deviceId));
  // Only a click starts a shell: the Terminal button's, or Connect here.
  const [session, setSession] = useState<Session | null>(() => (launch && !launch.record ? { record: false, n: 0 } : null));
  // Whether the next connection is recorded: only ever the user's explicit choice.
  const [record, setRecord] = useState(launch?.record ?? false);
  // The hub's own word that this session is recorded, and whether the recording is full.
  const [recording, setRecording] = useState<{ id: string; full: boolean } | null>(null);
  const [notice, setNotice] = useState('');
  const allowed = terminalTransportAllowed();
  const armed = allowed && session !== null;
  const aiOn = ai.data?.enabled === true;
  const name = device ? displayName(device) : deviceId;
  const ended = status.kind === 'ended';
  const recs = useRecordings(deviceId, ended && recording !== null);
  const rec = recording ? recs.data?.find((r) => r.id === recording.id && r.ended) : undefined;

  const connect = (withRecording: boolean) => {
    setNotice('');
    if (!withRecording) {
      setSession({ record: false, n: Date.now() });
      return;
    }
    // A recorded session asks for the password before it opens.
    withReauth(() => Promise.resolve())
      .then(() => {
        setSession({ record: true, n: Date.now() });
      })
      .catch((err: unknown) => {
        setNotice(err instanceof Error ? err.message : String(err));
      });
  };

  // A launch that asked for a recording connects once the password is in.
  const launched = useRef(false);
  useEffect(() => {
    if (launch?.record && allowed && !launched.current) {
      launched.current = true;
      connect(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once, on the launch
  }, []);

  useEffect(() => {
    document.title = `${name} · Terminal · Hearth`;
    return () => {
      // Make a runbook opens the editor in this tab.
      document.title = 'Hearth';
    };
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
    setRecording(null);
    const conn = openTerminal(
      deviceId,
      { rows: term.rows, cols: term.cols },
      (data) => {
        term.write(data);
      },
      (ev) => {
        if (ev.type === 'recording_full') {
          setRecording((r) => (r ? { ...r, full: true } : r));
          return;
        }
        if (ev.type === 'started' && ev.recording) {
          setRecording({ id: ev.recording, full: false });
        }
        if (ev.type === 'error' && ev.code === 'reauth_required') {
          // The hub holds no re-authentication (it restarted): ask for the password on Connect.
          forgetReauth();
        }
        const s = statusOf(ev);
        setStatus(s);
        if (s.kind === 'open') {
          term.focus();
        } else if (s.kind === 'ended') {
          term.write(`\r\n\x1b[2m[${s.message}]\x1b[0m\r\n`);
        }
      },
      session.record,
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
  }, [deviceId, armed, session, forgetReauth]);

  const recordToggle =
    ai.data === undefined ? null : aiOn ? (
      <label className="terminal-record small">
        <input
          type="checkbox"
          checked={record}
          onChange={(e) => {
            setRecord(e.target.checked);
          }}
        />
        Record for a runbook
      </label>
    ) : (
      <span className="small muted">
        Recording for a runbook needs AI: <a href="#/settings/ai">Settings, AI</a>
      </span>
    );

  return (
    <div className="terminal-page">
      <ReauthHost />
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
            ) : notice ? (
              <span className="danger-text">{notice}</span>
            ) : !armed ? (
              <span className="muted">
                Not connected. Connecting starts a shell on this device
                {record ? ', recorded for a runbook: what the screen shows is kept for an hour' : ''}.
              </span>
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
        {recording && !ended ? (
          <span
            className="recording-badge"
            role="status"
            title="What this terminal shows is recorded, never what you type at a hidden password prompt. It is kept in the hub's memory for an hour after the session, until you make a runbook from it."
          >
            <span className="recording-dot" aria-hidden="true" />
            {recording.full ? 'Recording full: the rest is not recorded' : 'Recording for a runbook'}
          </span>
        ) : null}
        {allowed && (!armed || ended) ? recordToggle : null}
        {allowed && !armed ? (
          <button
            className="btn btn-primary"
            type="button"
            onClick={() => {
              connect(record);
            }}
          >
            Connect
          </button>
        ) : armed && ended ? (
          <button
            className="btn btn-primary"
            type="button"
            onClick={() => {
              connect(record);
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
      {recording && ended ? (
        <section className="terminal-after" aria-label="Make a runbook">
          <p className="small">
            <strong>This session was recorded for a runbook.</strong>{' '}
            <span className="muted">
              Make a runbook from it, or discard it. The draft opens unsaved in the runbook editor.
            </span>
          </p>
          {rec ? (
            <MakeRunbook device={deviceId} recording={rec} />
          ) : recs.isPending ? (
            <p className="muted small">Loading the recording…</p>
          ) : (
            <p className="muted small">The recording is gone: it was used, discarded or expired.</p>
          )}
        </section>
      ) : null}
      <div className="terminal-host" ref={host} />
    </div>
  );
}
