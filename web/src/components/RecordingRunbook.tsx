// Runbook drafts from terminal sessions recorded for one (#81): the Make a
// runbook form, on the terminal once its session ended and on the device's
// page, and the device's list of recordings.

import { useState } from 'react';
import { useAIConfig, useDiscardRecording, useDraftRunbook, useRecordings, type Recording } from '../api/ai.ts';
import type { Device } from '../api/client.ts';
import { markTerminalLaunch, terminalTransportAllowed } from '../api/terminal.ts';
import { stashRunbookDraft } from '../runbookdraft.ts';
import { Tip } from './Tip.tsx';
import './DeviceExplain.css';
import './RecordingRunbook.css';

function clock(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function size(bytes: number): string {
  return bytes < 1024 ? `${String(bytes)} B` : `${String(Math.round(bytes / 1024))} KiB`;
}

/**
 * Drafts a runbook from an ended recording: the draft opens unsaved in the
 * runbook editor, in this tab. Preview shows what would be sent and keeps
 * the recording; a draft deletes it.
 */
export function MakeRunbook({ device, recording }: { device: string; recording: Recording }) {
  const draft = useDraftRunbook(device);
  const discard = useDiscardRecording(device);
  const [notes, setNotes] = useState('');
  const [discarded, setDiscarded] = useState(false);
  // A draft the editor could not be handed (no session storage): shown here to copy.
  const [unstashed, setUnstashed] = useState('');
  const res = draft.data;
  const where = res ? `${res.provider} ${res.model} at ${res.base_url}` : '';
  const busy = draft.isPending || discard.isPending;

  if (discarded) {
    return (
      <p className="muted small" role="status">
        The recording was deleted.
      </p>
    );
  }
  const run = (preview: boolean) => {
    draft.mutate(
      { id: recording.id, notes, preview },
      {
        onSuccess: (d) => {
          if (d.preview) {
            return;
          }
          if (!stashRunbookDraft(d)) {
            setUnstashed(d.yaml);
            return;
          }
          window.location.hash = '#/runbooks/new';
        },
      },
    );
  };
  return (
    <div className="explain-result">
      <form
        className="explain-form"
        onSubmit={(e) => {
          e.preventDefault();
          run(false);
        }}
      >
        <label className="field">
          What did the session do? (optional)
          <textarea
            rows={2}
            maxLength={2000}
            placeholder="Added a k3s worker node"
            value={notes}
            onChange={(e) => {
              setNotes(e.target.value);
            }}
          />
        </label>
        <div className="explain-actions">
          <button className="btn btn-primary" type="submit" disabled={busy}>
            {draft.isPending ? 'Drafting…' : 'Make a runbook'}
          </button>
          <button
            className="btn btn-ghost"
            type="button"
            disabled={busy}
            onClick={() => {
              run(true);
            }}
          >
            Preview what is sent
          </button>
          <button
            className="btn btn-ghost"
            type="button"
            disabled={busy}
            onClick={() => {
              discard.mutate(recording.id, {
                onSuccess: () => {
                  setDiscarded(true);
                },
              });
            }}
          >
            Discard
          </button>
          <span className="muted small">
            {size(recording.bytes)}
            {recording.full ? ' (full)' : ''}
            {recording.expires ? ` · deleted at ${clock(recording.expires)} if unused` : ''}
          </span>
        </div>
      </form>
      {draft.isError ? (
        <p className="error" role="alert">
          No draft: {draft.error.message}
        </p>
      ) : null}
      {discard.isError ? (
        <p className="error" role="alert">
          Not discarded: {discard.error.message}
        </p>
      ) : null}
      {unstashed ? (
        <>
          <p className="error" role="alert">
            The draft could not be handed to the runbook editor (this browser keeps no session storage): copy it from
            here into a new runbook.
          </p>
          <pre className="explain-sent">{unstashed}</pre>
        </>
      ) : null}
      {res?.preview ? (
        <>
          <p className="notice" role="status">
            <span>
              This is what would be sent to {where}: {res.sent_bytes} bytes, {res.redactions} value
              {res.redactions === 1 ? '' : 's'} redacted. Nothing has been sent yet. Redaction catches known secret
              formats only: check the transcript below.
            </span>
          </p>
          {res.truncated.length > 0 ? <p className="muted small">Cut to fit: {res.truncated.join(', ')}.</p> : null}
          <details className="explain-sent" open>
            <summary>
              What would be sent: {res.sent_bytes} bytes to {where}
            </summary>
            <pre>{[res.sent.system, ...res.sent.messages.map((m) => `--- ${m.role} ---\n${m.content}`)].join('\n\n')}</pre>
          </details>
        </>
      ) : null}
    </div>
  );
}

/** The device's recorded sessions, if any, each with Make a runbook. Nothing when there are none. */
export function DeviceRecordings({ device }: { device: string }) {
  const ai = useAIConfig();
  const list = useRecordings(device, ai.data?.enabled === true);
  const recs = list.data ?? [];
  if (recs.length === 0) {
    return null;
  }
  return (
    <section className="panel-card card-wide" aria-labelledby="recordings-title">
      <h2 className="card-label" id="recordings-title">
        Recorded for a runbook <Tip id="airecord" />
      </h2>
      {recs.map((r) =>
        r.ended ? (
          <div key={r.id}>
            <p className="small">
              Session from {clock(r.started)} to {clock(r.ended)} <span className="mono muted">{r.id}</span>
            </p>
            <MakeRunbook device={device} recording={r} />
          </div>
        ) : (
          <p key={r.id} className="small" role="status">
            <span className="recording-dot" aria-hidden="true" /> A terminal on this device is being recorded for a runbook,
            since {clock(r.started)} <span className="mono muted">{r.id}</span>
          </p>
        ),
      )}
    </section>
  );
}

/**
 * Opens the device's terminal in a new tab, recorded for a runbook: shown
 * only where the plain Terminal button would open one, and AI is on.
 */
export function RecordTerminalButton({ device }: { device: Device }) {
  const ai = useAIConfig();
  if (device.status !== 'online' || !device.facts.ceiling?.shell || !terminalTransportAllowed() || ai.data?.enabled !== true) {
    return null;
  }
  return (
    <a
      className="btn btn-ghost"
      style={{ textDecoration: 'none' }}
      href={`#/terminal/${encodeURIComponent(device.id)}`}
      target="_blank"
      rel="noopener"
      title="Opens a terminal whose screen is recorded, to make a runbook from what you do. It asks for your password."
      onClick={() => {
        markTerminalLaunch(device.id, true);
      }}
    >
      <span className="recording-dot" aria-hidden="true" />
      Record for a runbook
    </a>
  );
}
