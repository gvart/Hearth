import { useState } from 'react';
import { ApiError } from '../api/client.ts';
import { useClusterCA, useClusterCAStep } from '../api/cluster.ts';
import {
  caRefusalMessage,
  caStepEffect,
  caSteps,
  hubProgress,
  shortFP,
  waitingFor,
  type CAStep,
  type ClusterCA,
} from '../cluster.ts';
import { Modal } from './Modal.tsx';

const stepLabels: Record<CAStep, string> = { rotate: 'Start rotation', finish: 'Finish rotation', abort: 'Abort rotation' };

const stepTitles: Record<CAStep, string> = {
  rotate: 'Start a hub CA rotation',
  finish: 'Finish the hub CA rotation',
  abort: 'Abort the hub CA rotation',
};

function when(iso: string): string {
  return new Date(iso).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
}

/** The hub CA rotation: its stage, owner and every member's progress, and its steps. */
export function ClusterCASection() {
  const q = useClusterCA();
  const [step, setStep] = useState<CAStep>();
  const st = q.data;
  const rot = st?.rotation;
  const self = st?.hubs.find((h) => h.id === st.node_id);

  return (
    <section className="unmanaged" aria-labelledby="ca-title">
      <div className="section-head">
        <h2 id="ca-title">Hub CA</h2>
        {st ? (
          <p className="muted">
            {rot?.active
              ? `Rotation under way, owned by ${rot.owner}`
              : `${self?.serving ? `Serving CA ${self.serving} · ` : ''}${
                  rot ? `last rotation ${rot.stage} ${when(rot.updated_at)}` : 'never rotated'
                }`}
          </p>
        ) : null}
      </div>

      {q.isError ? (
        <div className="error-box" role="alert">
          Could not load the hub CA: {q.error.message}
        </div>
      ) : !st ? (
        <p className="muted">Loading the hub CA…</p>
      ) : (
        <>
          {rot?.active ? <RotationProgress st={st} /> : null}
          <div className="ca-actions">
            {caSteps(st).map((s) => (
              <button
                key={s}
                type="button"
                className={`btn${s === 'abort' ? ' btn-danger' : ''}`}
                onClick={() => {
                  setStep(s);
                }}
              >
                {stepLabels[s]}
              </button>
            ))}
            {!rot?.active ? (
              <span className="muted small">
                Replaces the CA every hub and agent trusts, without downtime. Rotate when a master&apos;s data dir or a
                backup with the CA key may have leaked.
              </span>
            ) : null}
          </div>
        </>
      )}

      {step && st ? (
        <CAStepDialog
          step={step}
          st={st}
          onClose={() => {
            setStep(undefined);
          }}
        />
      ) : null}
    </section>
  );
}

function RotationProgress({ st }: { st: ClusterCA }) {
  const rot = st.rotation;
  if (!rot) {
    return null;
  }
  const waiting = waitingFor(st);
  const old = st.old_devices ?? [];
  const owner = rot.owner === st.node_id ? 'this hub' : rot.owner_alive ? 'alive' : 'not alive';
  return (
    <>
      <dl className="ca-facts">
        <dt>Stage</dt>
        <dd>
          <span className={`pill pill-${rot.stage === 'cutover' ? 'warn' : 'muted'}`}>{rot.stage}</span>
        </dd>
        <dt>Owner</dt>
        <dd>
          {rot.owner} <span className="muted small">({owner})</span>
        </dd>
        <dt>Started</dt>
        <dd>{when(rot.started_at)}</dd>
        <dt>New CA</dt>
        <dd className="mono">{shortFP(rot.new_ca_fp)}</dd>
      </dl>
      <div className="table-wrap">
        <table className="devices kube cluster-table">
          <thead>
            <tr>
              <th>Member</th>
              <th>Role</th>
              <th>Progress</th>
            </tr>
          </thead>
          <tbody>
            {st.hubs.map((h) => {
              const p = hubProgress(h, rot);
              return (
                <tr key={h.id}>
                  <td>
                    <span className="name">
                      {h.id}
                      {h.id === st.node_id ? <span className="muted small"> (this hub)</span> : null}
                    </span>
                  </td>
                  <td className="muted">{h.master ? 'master' : 'storage'}</td>
                  <td>
                    <span className={`pill pill-${p.tone}`}>{p.label}</span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className={`small ${waiting.length > 0 ? 'ca-waiting' : 'muted'}`} role="status">
        {waiting.length > 0
          ? `A finish waits for: ${waiting.join(', ')}.`
          : 'Every member is ready for the finish.'}
      </p>
      {old.length > 0 ? (
        <p className="small ca-waiting">
          {old.length} agent{old.length === 1 ? '' : 's'} not renewed yet: {old.slice(0, 8).join(', ')}
          {old.length > 8 ? ', …' : ''}. Each renews when it connects; the finish refuses while any are left.
        </p>
      ) : null}
    </>
  );
}

/** Confirms a step of the rotation, then asks this master, with the password again. */
function CAStepDialog({ step, st, onClose }: { step: CAStep; st: ClusterCA; onClose: () => void }) {
  const run = useClusterCAStep();
  const err = run.error;
  const waiting = step === 'finish' ? waitingFor(st) : [];
  const old = step === 'finish' ? (st.old_devices ?? []) : [];

  return (
    <Modal className="dialog" labelledBy="ca-step-title" onClose={onClose}>
      <header className="dialog-head">
        <div>
          <h2 id="ca-step-title">{stepTitles[step]}</h2>
          <p className="muted small">
            {st.hubs.length} member{st.hubs.length === 1 ? '' : 's'}
            {st.rotation?.active ? ` · new CA ${shortFP(st.rotation.new_ca_fp)} · owned by ${st.rotation.owner}` : ''}
          </p>
        </div>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          run.mutate(step);
        }}
      >
        <section className="plan" aria-label="What this does">
          <div className="plan-head">
            <span className="muted small">What this does</span>
            <span className="pill pill-bad">dangerous</span>
          </div>
          {caStepEffect(step).map((line) => (
            <p key={line}>{line}</p>
          ))}
          {waiting.length > 0 || old.length > 0 ? (
            <ul className="plan-warnings">
              {waiting.length > 0 ? <li>Not ready yet: {waiting.join(', ')}.</li> : null}
              {old.length > 0 ? (
                <li>
                  {old.length} agent{old.length === 1 ? '' : 's'} not renewed yet: the finish refuses until they are.
                </li>
              ) : null}
            </ul>
          ) : null}
        </section>

        {err ? (
          <div className="error-box" role="alert">
            {err instanceof ApiError ? caRefusalMessage(err.code, err.message, st.rotation) : err.message}
          </div>
        ) : null}
        {run.isSuccess ? (
          <div className="ok-box" role="status">
            {doneMessage(step)}
          </div>
        ) : null}
        {run.isPending ? (
          <p className="muted small" role="status">
            Waiting for an answer.{step === 'finish' ? ' A finish waits for every member, up to two minutes.' : ''} If
            policy holds this action, approve it on the Approvals page.
          </p>
        ) : null}

        <div className="form-actions">
          <button className="btn btn-ghost" type="button" onClick={onClose}>
            {run.isSuccess ? 'Close' : 'Cancel'}
          </button>
          {run.isSuccess ? null : (
            <button className="btn btn-danger" type="submit" disabled={run.isPending}>
              {run.isPending ? `${stepLabels[step]}…` : stepLabels[step]}
            </button>
          )}
        </div>
      </form>
    </Modal>
  );
}

function doneMessage(step: CAStep): string {
  switch (step) {
    case 'rotate':
      return 'Rotation started. The members fetch the new CA now: follow their progress on this page, then finish.';
    case 'finish':
      return 'Rotation finished. Every member serves the new CA; fetch it again from /ca.crt where a browser trusted the old one.';
    case 'abort':
      return 'Rotation aborted. Every member dropped the new CA.';
  }
}
