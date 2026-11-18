import { useState } from 'react';
import type { KubeActionName, KubeActionRequest, KubeCluster } from '../api/client.ts';
import { useKubeAction, useKubeActionPlan } from '../api/hooks.ts';
import { Modal } from './Modal.tsx';

const verbs: Record<KubeActionName, string> = {
  restart: 'Restart',
  scale: 'Scale',
  delete_pod: 'Delete pod',
  cordon: 'Cordon',
  uncordon: 'Uncordon',
  drain: 'Drain node',
};

const drainTimeouts = [60, 120, 300, 600];

function title(req: KubeActionRequest): string {
  switch (req.action) {
    case 'restart':
    case 'scale':
      return `${verbs[req.action]} ${req.kind ?? ''} ${req.namespace ?? ''}/${req.name}`;
    case 'delete_pod':
      return `Delete pod ${req.namespace ?? ''}/${req.name}`;
    default:
      return `${verbs[req.action]} ${req.name}`;
  }
}

/**
 * Confirms a Kubernetes action: it shows the action's dry run first, then
 * carries it out on confirmation.
 */
export function KubeActionDialog({
  cluster,
  request,
  onClose,
}: {
  cluster: KubeCluster;
  request: KubeActionRequest;
  onClose: () => void;
}) {
  const [replicas, setReplicas] = useState(String(request.replicas ?? 1));
  const [timeout, setDrainTimeout] = useState(120);
  const replicasOk = /^\d{1,6}$/.test(replicas);
  const req: KubeActionRequest = {
    ...request,
    ...(request.action === 'scale' ? { replicas: Number(replicas) } : {}),
    ...(request.action === 'drain' ? { timeout_seconds: timeout } : {}),
  };
  const act = useKubeAction(cluster.id);
  const plan = useKubeActionPlan(cluster.id, req, replicasOk && !act.isSuccess);
  const p = plan.data;
  const dangerous = p?.class === 'dangerous';
  const nothingToDo = p !== undefined && p.steps.length === 0;

  return (
    <Modal className="dialog" labelledBy="kube-action-title" onClose={onClose}>
      <header className="dialog-head">
        <div>
          <h2 id="kube-action-title">{title(request)}</h2>
          <p className="muted small">{cluster.name}</p>
        </div>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          act.mutate(req);
        }}
      >
        {request.action === 'scale' ? (
          <label className="field">
            <span>Replicas</span>
            <input
              type="number"
              min={0}
              inputMode="numeric"
              value={replicas}
              aria-invalid={!replicasOk}
              disabled={act.isPending || act.isSuccess}
              onChange={(e) => {
                setReplicas(e.target.value);
              }}
            />
          </label>
        ) : null}
        {request.action === 'drain' ? (
          <label className="ns-filter">
            <span className="muted small">Give up after</span>
            <select
              value={timeout}
              disabled={act.isPending || act.isSuccess}
              onChange={(e) => {
                setDrainTimeout(Number(e.target.value));
              }}
            >
              {drainTimeouts.map((s) => (
                <option key={s} value={s}>
                  {s / 60} min
                </option>
              ))}
            </select>
          </label>
        ) : null}

        <section className="plan" aria-label="Dry run" aria-busy={plan.isFetching}>
          <div className="plan-head">
            <span className="muted small">Dry run</span>
            {p ? <span className={`pill pill-${dangerous ? 'bad' : 'ok'}`}>{p.class}</span> : null}
          </div>
          {!replicasOk ? (
            <p className="muted">Enter a number of replicas.</p>
          ) : plan.isError ? (
            <div className="error-box" role="alert">
              {plan.error.message}
            </div>
          ) : !p ? (
            <p className="muted">Planning…</p>
          ) : (
            <>
              <p>{p.summary}</p>
              {p.steps.length > 0 ? (
                <ol className="plan-steps small">
                  {p.steps.map((s) => (
                    <li key={s}>{s}</li>
                  ))}
                </ol>
              ) : null}
              {p.warnings.length > 0 ? (
                <ul className="plan-warnings small">
                  {p.warnings.map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              ) : null}
            </>
          )}
        </section>

        {act.isError ? (
          <div className="error-box" role="alert">
            {act.error.message}
          </div>
        ) : null}
        {act.isSuccess ? (
          <div className="ok-box" role="status">
            {act.data.result}
          </div>
        ) : null}
        {act.isPending && request.action === 'drain' ? (
          <p className="muted small" role="status">
            Evicting pods, waiting up to {timeout / 60} min for them to go…
          </p>
        ) : null}

        <div className="form-actions">
          <button className="btn btn-ghost" type="button" onClick={onClose}>
            {act.isSuccess ? 'Close' : 'Cancel'}
          </button>
          {act.isSuccess ? null : (
            <button
              className={`btn ${dangerous ? 'btn-danger' : 'btn-primary'}`}
              type="submit"
              disabled={!p || plan.isFetching || nothingToDo || act.isPending}
            >
              {act.isPending ? `${verbs[request.action]}…` : verbs[request.action]}
            </button>
          )}
        </div>
      </form>
    </Modal>
  );
}
