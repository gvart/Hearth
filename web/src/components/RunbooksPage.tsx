import { useEffect, useRef, useState, type SyntheticEvent } from 'react';
import { api, type Runbook, type RunbookPlanStep, type RunbookRun, type RunbookStep } from '../api/client.ts';
import {
  useRunbookPlan,
  useRunbookRun,
  useRunbookRunAction,
  useRunbookRuns,
  useRunbooks,
  useStartRunbook,
} from '../api/hooks.ts';
import { useRunbookFiles } from '../api/admin.ts';
import { formatDateTime, relativeTime, timeLeft } from '../format.ts';
import { planOfHash } from '../nav.ts';
import { RunbookEditor } from './RunbookEditor.tsx';
import './RunbooksPage.css';

const runHash = '#/runbooks/run/';
const editHash = '#/runbooks/edit/';
const newHash = '#/runbooks/new';

/** The URL hash, kept current. */
function useHash(): string {
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const onHash = () => {
      setHash(window.location.hash);
    };
    window.addEventListener('hashchange', onHash);
    return () => {
      window.removeEventListener('hashchange', onHash);
    };
  }, []);
  return hash;
}

/** The current time, ticking every second while mounted. */
function useNow(): number {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const t = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => {
      clearInterval(t);
    };
  }, []);
  return now;
}

/** The run the URL points at, if any, so a reload or a link keeps it open. */
function useOpenRun(): string {
  const read = () => (window.location.hash.startsWith(runHash) ? window.location.hash.slice(runHash.length) : '');
  const [id, setId] = useState(read);
  useEffect(() => {
    const onHash = () => {
      setId(read());
    };
    window.addEventListener('hashchange', onHash);
    return () => {
      window.removeEventListener('hashchange', onHash);
    };
  }, []);
  return id;
}

function pillOf(status: string): string {
  switch (status) {
    case 'ok':
    case 'succeeded':
    case 'rolled_back':
      return 'pill-ok';
    case 'failed':
    case 'denied':
    case 'rollback_failed':
    case 'unknown':
      return 'pill-bad';
    case 'running':
    case 'waiting':
    case 'rolling_back':
      return 'pill-warn';
    default:
      return 'pill-muted';
  }
}

function Status({ status }: { status: string }) {
  return <span className={`pill ${pillOf(status)}`}>{status.replace('_', ' ')}</span>;
}

/** The runbooks on the hub and their recent runs, or the run the URL opens. */
export function RunbooksPage() {
  const open = useOpenRun();
  const hash = useHash();
  if (hash === newHash) {
    return <RunbookEditor key="new" />;
  }
  if (hash.startsWith(editHash)) {
    const file = decodeURIComponent(hash.slice(editHash.length));
    return <RunbookEditor key={file} file={file} />;
  }
  return open ? <RunPage key={open} id={open} /> : <ListPage />;
}

function ListPage() {
  const runbooks = useRunbooks();
  const runs = useRunbookRuns();
  const list = runbooks.data?.runbooks ?? [];
  const now = useNow();
  // A plan link (#/runbooks/plan/<id>) opens that runbook's plan.
  const planned = planOfHash(useHash());
  // Absent on a hub that keeps its configuration in files.
  const files = useRunbookFiles();
  const fileOf = (id: string) => files.data?.find((f) => f.id === id)?.file;

  return (
    <main className="content">
      <div className="page-head">
        <div>
          <h1>Runbooks</h1>
          <p className="muted">Step-by-step procedures with checks, prompts and rollback.</p>
        </div>
        {files.isSuccess ? (
          <a className="btn btn-primary runbooks-new" href={newHash}>
            New runbook
          </a>
        ) : null}
      </div>

      {runbooks.data?.errors.map((e) => (
        <div key={e} className="error-box" role="alert">
          {e}
        </div>
      ))}
      {runbooks.isError ? (
        <div className="error-box" role="alert">
          Could not load runbooks: {runbooks.error.message}
        </div>
      ) : runbooks.isPending ? (
        <p className="muted">Loading runbooks…</p>
      ) : list.length === 0 ? (
        <div className="empty">
          <h2>No runbooks yet</h2>
          <p className="muted">
            Put runbook YAML files in the hub&apos;s runbooks directory (<code>--runbooks-dir</code>) and they appear
            here.
          </p>
        </div>
      ) : (
        <ul className="runbook-list">
          {list.map((r) => (
            <RunbookCard
              // Remounted when a link asks for its plan, so the plan opens.
              key={r.id === planned ? `${r.id}:plan` : r.id}
              runbook={r}
              file={fileOf(r.id)}
              planned={r.id === planned}
            />
          ))}
        </ul>
      )}

      <h2 className="section-title">Recent runs</h2>
      {runs.isError ? (
        <div className="error-box" role="alert">
          Could not load runs: {runs.error.message}
        </div>
      ) : !runs.data || runs.data.length === 0 ? (
        <p className="muted">{runs.isPending ? 'Loading…' : 'No runs yet.'}</p>
      ) : (
        <ul className="runbook-list">
          {runs.data.map((r) => (
            <li key={r.id} className="runbook-card">
              <div className="runbook-row">
                <a className="mono" href={runHash + encodeURIComponent(r.id)}>
                  {r.runbook_id}
                </a>
                <Status status={r.status} />
              </div>
              <span className="muted small" title={formatDateTime(r.started_at)}>
                Started {relativeTime(r.started_at, now)} by {r.started_by}
              </span>
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}

function RunbookCard({ runbook, file, planned }: { runbook: Runbook; file?: string; planned: boolean }) {
  const [planning, setPlanning] = useState(planned);
  const start = useStartRunbook();
  const card = useRef<HTMLLIElement>(null);
  // A link to this runbook's plan (the command bar makes them) brings the card into view.
  useEffect(() => {
    if (planned) {
      card.current?.scrollIntoView({ block: 'center' });
    }
  }, [planned]);
  return (
    <li ref={card} className={planned ? 'runbook-card runbook-card-planned' : 'runbook-card'}>
      <div className="runbook-row">
        <strong className="mono">{runbook.id}</strong>
        <span className="muted small">
          {runbook.steps} {runbook.steps === 1 ? 'step' : 'steps'}
        </span>
      </div>
      {runbook.description ? <p className="muted">{runbook.description}</p> : null}
      <div className="runbook-actions">
        <button
          className="btn"
          type="button"
          aria-expanded={planning}
          onClick={() => {
            setPlanning(!planning);
          }}
        >
          {planning ? 'Hide plan' : 'Plan'}
        </button>
        <button
          className="btn btn-primary"
          type="button"
          disabled={start.isPending}
          onClick={() => {
            start.mutate(runbook.id, {
              onSuccess: (run) => {
                window.location.hash = runHash + encodeURIComponent(run.id);
              },
            });
          }}
        >
          Start run
        </button>
        {file ? (
          <a className="btn btn-ghost" href={editHash + encodeURIComponent(file)}>
            Edit
          </a>
        ) : null}
      </div>
      {start.isError ? (
        <p className="error" role="alert">
          {start.error.message}
        </p>
      ) : null}
      {planning ? <Plan id={runbook.id} /> : null}
    </li>
  );
}

function Plan({ id }: { id: string }) {
  const plan = useRunbookPlan(id, true);
  if (plan.isError) {
    return (
      <p className="error" role="alert">
        Could not plan this runbook: {plan.error.message}
      </p>
    );
  }
  if (!plan.data) {
    return <p className="muted">Working out the plan…</p>;
  }
  return (
    <>
      <p className="muted small">Plan only: nothing has been executed.</p>
      <ol className="runbook-steps">
        {plan.data.steps.map((s) => (
          <li key={s.id} className="runbook-step">
            <PlanStep step={s} />
            {s.rollback ? (
              <div className="runbook-sub">
                <span className="muted small">Rollback</span>
                <PlanStep step={s.rollback} />
              </div>
            ) : null}
          </li>
        ))}
      </ol>
    </>
  );
}

const decisionPill = { allow: 'pill-ok', confirm: 'pill-warn', deny: 'pill-bad' } as const;

function PlanStep({ step }: { step: RunbookPlanStep }) {
  return (
    <>
      <div className="runbook-row">
        <span>
          <strong>{step.id}</strong> <span className="muted small">{step.type}</span>
        </span>
        {step.decision ? <span className={`pill ${decisionPill[step.decision]}`}>policy: {step.decision}</span> : null}
      </div>
      <span className="small">{step.what}</span>
      {step.action ? (
        <span className="muted small mono">
          {step.action} ({step.class})
        </span>
      ) : null}
      {step.reason ? <span className="error">{step.reason}</span> : null}
    </>
  );
}

function RunPage({ id }: { id: string }) {
  const run = useRunbookRun(id);
  return (
    <main className="content">
      <p className="runbook-back">
        <a className="link" href="#/runbooks">
          Back to runbooks
        </a>
      </p>
      {run.isError ? (
        <div className="error-box" role="alert">
          Could not load this run: {run.error.message}
        </div>
      ) : !run.data ? (
        <p className="muted">Loading the run…</p>
      ) : (
        <RunDetail run={run.data} />
      )}
    </main>
  );
}

function RunDetail({ run }: { run: RunbookRun }) {
  const awaiting = run.steps.find((s) => s.id === run.awaiting);
  return (
    <>
      <div className="page-head">
        <div>
          <h1>{run.runbook_id}</h1>
          <p className="muted small" title={formatDateTime(run.started_at)}>
            Started by {run.started_by}
          </p>
        </div>
        <Status status={run.status} />
      </div>

      {run.can_retry || run.can_rollback || run.can_pass_over ? <Stopped run={run} /> : null}
      {awaiting?.prompt ? <Prompt key={awaiting.id} run={run} step={awaiting} /> : null}
      {run.error ? (
        <div className="error-box" role="alert">
          {run.error}
        </div>
      ) : null}

      <h2 className="section-title">Steps</h2>
      <ol className="runbook-steps">
        {run.steps.map((s) => (
          <Step key={s.id} step={s} />
        ))}
      </ol>

      <h2 className="section-title">Log</h2>
      <ol className="runbook-log" aria-label="Run log">
        {run.log.map((l, i) => (
          <li key={`${l.at}-${String(i)}`}>
            <span className="muted">{new Date(l.at).toLocaleTimeString()}</span>
            {l.step ? ` [${l.step}]` : ''}
            {l.actor ? ` ${l.actor}:` : ''} {l.message}
          </li>
        ))}
      </ol>
    </>
  );
}

function Step({ step }: { step: RunbookStep }) {
  const rollback = step.rollback;
  return (
    <li className="runbook-step">
      <div className="runbook-row">
        <span>
          <strong>{step.id}</strong> <span className="muted small">{step.type}</span>
        </span>
        <Status status={step.status} />
      </div>
      <span className="small">{step.what}</span>
      {step.attempts > 1 ? <span className="muted small">{step.attempts} attempts</span> : null}
      {step.error ? <pre className="runbook-step-error">{step.error}</pre> : null}
      {rollback && rollback.status !== 'pending' ? (
        <div className="runbook-sub">
          <div className="runbook-row">
            <span className="muted small">Rollback: {rollback.what}</span>
            <Status status={rollback.status} />
          </div>
          {rollback.error ? <pre className="runbook-step-error">{rollback.error}</pre> : null}
        </div>
      ) : null}
    </li>
  );
}

/** What an operator can do with a run that stopped. */
function Stopped({ run }: { run: RunbookRun }) {
  const retry = useRunbookRunAction(run.id, () => api.retryRunbookRun(run.id, run.version));
  const rollback = useRunbookRunAction(run.id, () => api.rollbackRunbookRun(run.id, run.version));
  const passOver = useRunbookRunAction(run.id, () => api.passOverRunbookStep(run.id, run.pass_over_step ?? '', run.version));
  const busy = retry.isPending || rollback.isPending || passOver.isPending;
  const inRollback = run.phase === 'rollback';
  const failure = retry.error ?? rollback.error ?? passOver.error;
  return (
    <section className="runbook-stopped" aria-label="Run stopped">
      <strong>{inRollback ? 'The rollback stopped' : 'The run stopped'}</strong>
      <p className="small">
        {run.status === 'unknown'
          ? 'No answer came back from this step, so it may or may not have happened. Check the device, then choose.'
          : inRollback
            ? 'Retry the rollback step, or pass over it and go on rolling back.'
            : 'Retry the step, or undo the completed steps through their rollback steps.'}
      </p>
      {failure ? (
        <p className="error" role="alert">
          {failure.message}
        </p>
      ) : null}
      <div className="runbook-actions">
        <button
          className="btn btn-primary"
          type="button"
          disabled={busy || !run.can_retry}
          onClick={() => {
            retry.mutate(undefined);
          }}
        >
          {inRollback ? 'Retry rollback step' : 'Retry step'}
        </button>
        {inRollback ? (
          <button
            className="btn"
            type="button"
            disabled={busy || !run.can_pass_over}
            onClick={() => {
              passOver.mutate(undefined);
            }}
          >
            Pass over and continue
          </button>
        ) : (
          <button
            className="btn"
            type="button"
            disabled={busy || !run.can_rollback}
            onClick={() => {
              rollback.mutate(undefined);
            }}
          >
            Roll back
          </button>
        )}
      </div>
    </section>
  );
}

/** Answers the prompt the run is waiting at. A secret answer is never kept here after it is sent. */
function Prompt({ run, step }: { run: RunbookRun; step: RunbookStep }) {
  const [value, setValue] = useState('');
  const now = useNow();
  const answer = useRunbookRunAction(run.id, (v: string) => api.answerRunbookPrompt(run.id, step.id, v));
  const prompt = step.prompt;
  if (!prompt) {
    return null;
  }
  const send = (v: string) => {
    answer.mutate(v, {
      onSettled: () => {
        setValue('');
      },
    });
  };
  const onSubmit = (e: SyntheticEvent) => {
    e.preventDefault();
    send(value);
  };
  return (
    <section className="runbook-prompt" aria-label="Prompt">
      <div className="runbook-row">
        <strong>{prompt.message}</strong>
        {run.deadline ? (
          <span className="pill pill-warn" title={formatDateTime(run.deadline)}>
            Expires in {timeLeft(run.deadline, now)}
          </span>
        ) : null}
      </div>
      {answer.isError ? (
        <p className="error" role="alert">
          {answer.error.message}
        </p>
      ) : null}
      {prompt.kind === 'confirm' ? (
        <div className="runbook-actions">
          <button
            className="btn btn-primary"
            type="button"
            disabled={answer.isPending}
            onClick={() => {
              send('yes');
            }}
          >
            Yes
          </button>
          <button
            className="btn"
            type="button"
            disabled={answer.isPending}
            onClick={() => {
              send('no');
            }}
          >
            No
          </button>
        </div>
      ) : (
        <form className="runbook-answer" onSubmit={onSubmit}>
          <label className="field">
            {prompt.secret ? 'Answer (secret, never stored)' : 'Answer'}
            <input
              type={prompt.secret ? 'password' : 'text'}
              autoComplete="off"
              value={value}
              onChange={(e) => {
                setValue(e.target.value);
              }}
            />
          </label>
          <button className="btn btn-primary" type="submit" disabled={answer.isPending || value === ''}>
            Send answer
          </button>
        </form>
      )}
    </section>
  );
}
