import { useState } from 'react';
import {
  problemsOf,
  useDeleteRunbook,
  useRunbookFile,
  useSaveRunbook,
  useValidateRunbook,
  type Validation,
} from '../api/admin.ts';
import type { RunbookPlanStep } from '../api/client.ts';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import { ProblemList } from './SettingsPage.tsx';
import './SettingsPage.css';

const listRoute = '#/runbooks';

const newRunbookYaml = `id: my-runbook
description: What this procedure does.
steps:
  - id: go-ahead
    type: prompt
    prompt: confirm
    message: Go ahead?
  - id: settle
    type: wait
    duration: 30s
`;

/** Opens a runbook file of the hub, or a new one. */
export function RunbookEditor({ file }: { file?: string }) {
  const doc = useRunbookFile(file);
  if (file === undefined) {
    return <Editor initial={newRunbookYaml} revision="" />;
  }
  if (doc.isPending) {
    return (
      <main className="content">
        <p className="muted">Loading {file}…</p>
      </main>
    );
  }
  if (doc.isError) {
    return (
      <main className="content">
        <div className="error-box" role="alert">
          Could not load {file}: {doc.error.message}
          <a href={listRoute}>Back to runbooks</a>
        </div>
      </main>
    );
  }
  return <Editor file={file} initial={doc.data.yaml} revision={doc.data.revision} />;
}

/** The file a new runbook goes in: its id.yaml. */
function fileOf(yaml: string): string {
  const id = /^id:\s*["']?([a-z0-9_-]+)["']?\s*$/m.exec(yaml)?.[1];
  return id ? `${id}.yaml` : '';
}

function Editor({ file, initial, revision: initialRevision }: { file?: string; initial: string; revision: string }) {
  const [yaml, setYaml] = useState(initial);
  const [revision, setRevision] = useState(initialRevision);
  const [checked, setChecked] = useState<Validation | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [note, setNote] = useState('');
  const validate = useValidateRunbook();
  const save = useSaveRunbook();
  const del = useDeleteRunbook();
  const target = file ?? fileOf(yaml);
  const problems = checked && !checked.valid ? checked.problems : problemsOf(save.error);

  const check = () => {
    setNote('');
    validate.mutate(
      { yaml, file: target },
      {
        onSuccess: (v) => {
          setChecked(v);
        },
      },
    );
  };

  return (
    <main className="content doc-editor">
      <div className="page-head">
        <div className="doc-title">
          <a className="muted small" href={listRoute}>
            Runbooks
          </a>
          <h1 className="mono">{file ?? 'New runbook'}</h1>
          <p className="muted small">{file ? 'A runbook file of the hub' : target ? `Will be saved as ${target}` : 'Not saved yet'}</p>
        </div>
        <div className="settings-actions">
          {file ? (
            <button
              className="btn btn-ghost"
              type="button"
              onClick={() => {
                setDeleting(true);
              }}
            >
              Delete
            </button>
          ) : null}
          <button className="btn" type="button" disabled={validate.isPending || target === ''} onClick={check}>
            {validate.isPending ? 'Checking…' : 'Check and plan'}
          </button>
          <button
            className="btn btn-primary"
            type="button"
            disabled={save.isPending || target === ''}
            onClick={() => {
              setNote('');
              validate.mutate(
                { yaml, file: target },
                {
                  onSuccess: (v) => {
                    setChecked(v);
                    setConfirming(v.valid);
                  },
                },
              );
            }}
          >
            Save…
          </button>
        </div>
      </div>

      {target === '' ? <p className="error">The file needs an id: lowercase letters, digits, - and _.</p> : null}
      {problems.length > 0 ? (
        <div className="error-box" role="alert">
          <strong>Not valid</strong>
          <ProblemList problems={problems} />
        </div>
      ) : null}
      {validate.isError ? (
        <div className="error-box" role="alert">
          {validate.error.message}
        </div>
      ) : null}
      {save.isError && problemsOf(save.error).length === 0 ? (
        <div className="error-box" role="alert">
          Not saved: {save.error.message}
        </div>
      ) : null}
      {note ? (
        <p className="notice" role="status">
          {note}
        </p>
      ) : null}
      {confirming ? (
        <div className="notice" role="status">
          <strong>The runbook is valid. Save {target}?</strong>
          <span>
            Saving is <code>config.import</code>, a dangerous action decided by policy. Every hub has the new file
            within seconds; runs already started keep the version they started from.
          </span>
          {save.isPending ? (
            <span className="muted small">Saving. If policy holds this for approval, approve it on the Approvals page.</span>
          ) : null}
          <div className="settings-actions">
            <button
              className="btn btn-danger"
              type="button"
              disabled={save.isPending}
              onClick={() => {
                save.mutate(
                  { file: target, yaml, revision },
                  {
                    onSuccess: (doc) => {
                      setRevision(doc.revision);
                      setConfirming(false);
                      setNote('Saved. Every hub has it within seconds.');
                      if (file === undefined) {
                        window.location.hash = `#/runbooks/edit/${encodeURIComponent(doc.file)}`;
                      }
                    },
                  },
                );
              }}
            >
              {save.isPending ? 'Saving…' : 'Save runbook'}
            </button>
            <button
              className="btn btn-ghost"
              type="button"
              onClick={() => {
                setConfirming(false);
              }}
            >
              Keep editing
            </button>
          </div>
        </div>
      ) : null}
      {checked?.valid && checked.plan ? (
        <section aria-label="Plan">
          <p className="muted small">Plan only: nothing has been executed.</p>
          <ol className="runbook-steps">
            {checked.plan.steps.map((s) => (
              <li key={s.id} className="runbook-step">
                <PlanLine step={s} />
                {s.rollback ? (
                  <div className="runbook-sub">
                    <span className="muted small">Rollback</span>
                    <PlanLine step={s.rollback} />
                  </div>
                ) : null}
              </li>
            ))}
          </ol>
        </section>
      ) : null}

      <label className="field">
        Runbook file
        <textarea
          className="doc-yaml"
          value={yaml}
          rows={Math.min(32, Math.max(14, yaml.split('\n').length + 2))}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          wrap="off"
          aria-invalid={problems.length > 0}
          onChange={(e) => {
            setYaml(e.target.value);
            setChecked(null);
            setConfirming(false);
            setNote('');
            save.reset();
          }}
        />
      </label>
      <p className="muted small">
        See <a href="https://github.com/gvart/hearth/blob/main/docs/runbooks.md">docs/runbooks.md</a> for the steps a
        runbook can take.
      </p>

      {deleting && file ? (
        <ConfirmDialog
          title={`Delete ${file}`}
          actionClass="dangerous"
          confirmLabel="Delete runbook"
          pendingLabel="Deleting…"
          pending={del.isPending}
          error={del.isError ? del.error.message : undefined}
          onConfirm={() => {
            del.mutate(file, {
              onSuccess: () => {
                window.location.hash = listRoute;
              },
            });
          }}
          onClose={() => {
            setDeleting(false);
          }}
        >
          <p>
            Every hub stops offering this runbook within seconds. Runs already started keep their own copy and can
            finish. Deleting is <code>config.import</code>, decided by policy and audited.
          </p>
        </ConfirmDialog>
      ) : null}
    </main>
  );
}

const decisionPill = { allow: 'pill-ok', confirm: 'pill-warn', deny: 'pill-bad' } as const;

function PlanLine({ step }: { step: RunbookPlanStep }) {
  return (
    <>
      <div className="runbook-row">
        <span>
          <strong>{step.id}</strong> <span className="muted small">{step.type}</span>
        </span>
        {step.decision ? <span className={`pill ${decisionPill[step.decision]}`}>policy: {step.decision}</span> : null}
      </div>
      <span className="small">{step.what}</span>
      {step.reason ? <span className="error">{step.reason}</span> : null}
    </>
  );
}
