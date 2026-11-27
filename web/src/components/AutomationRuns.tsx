import { useState } from 'react';
import { useAutomationRuns, useDeleteAutomation } from '../api/admin.ts';
import { formatDateTime } from '../format.ts';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import './SettingsPage.css';

function pillOf(status: string): string {
  switch (status) {
    case 'ok':
    case 'succeeded':
      return 'pill-ok';
    case 'failed':
    case 'denied':
      return 'pill-bad';
    case 'running':
    case 'waiting':
      return 'pill-warn';
    default:
      return 'pill-muted';
  }
}

/** The recent runs of an automation, as `hearth automation runs` lists them. */
export function AutomationRuns({ id }: { id: string }) {
  const runs = useAutomationRuns(id);
  const list = runs.data ?? [];
  return (
    <section className="auto-runs" aria-labelledby="auto-runs-title">
      <h2 id="auto-runs-title" className="section-title">
        Recent runs
      </h2>
      {runs.isError ? (
        <p className="error" role="alert">
          Could not load runs: {runs.error.message}
        </p>
      ) : list.length === 0 ? (
        <p className="muted small">{runs.isPending ? 'Loading…' : 'No runs yet.'}</p>
      ) : (
        <ol>
          {list.map((r) => (
            <li key={r.id} className="auto-run">
              <div className="auto-run-head">
                <span className="small">
                  {formatDateTime(r.started_at)} <span className="muted">· trigger</span>{' '}
                  <span className="mono">{r.trigger_id || '-'}</span>
                </span>
                <span className={`pill ${pillOf(r.status)}`}>{r.status}</span>
              </div>
              {r.steps[0]?.ran_on ? (
                <span className="muted small">
                  Ran on the device{r.steps[0].hub_unreachable ? ' while the hub was unreachable' : ''}
                </span>
              ) : null}
              {r.error ? <span className="error small">{r.error}</span> : null}
              {r.steps.length > 0 ? (
                <div className="auto-run-steps">
                  {r.steps.map((s, i) => (
                    <span
                      key={`${s.id}-${String(i)}`}
                      className={`pill ${pillOf(s.status)}`}
                      title={s.error ? `${s.type}: ${s.error}` : s.type}
                    >
                      {s.id || s.type}: {s.status}
                    </span>
                  ))}
                </div>
              ) : null}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

/** Deletes an automation, as `hearth config delete` does. */
export function DeleteAutomationButton({ id, disabled }: { id: string; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  const del = useDeleteAutomation();
  return (
    <>
      <button
        type="button"
        className="btn btn-ghost"
        disabled={disabled}
        onClick={() => {
          del.reset();
          setOpen(true);
        }}
      >
        Delete
      </button>
      {open ? (
        <ConfirmDialog
          title={`Delete ${id}`}
          actionClass="dangerous"
          confirmLabel="Delete automation"
          pendingLabel="Deleting…"
          pending={del.isPending}
          error={del.isError ? del.error.message : undefined}
          onConfirm={() => {
            del.mutate(id, {
              onSuccess: () => {
                window.location.hash = '#/automations';
              },
            });
          }}
          onClose={() => {
            setOpen(false);
          }}
        >
          <p>
            Every hub stops running <strong className="mono">{id}</strong> within seconds; its run history stays.
            Deleting is <code>config.import</code>, decided by policy and audited.
          </p>
        </ConfirmDialog>
      ) : null}
    </>
  );
}
