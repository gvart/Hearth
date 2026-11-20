import { useDockerAction, type DockerActionName, type DockerContainer } from '../api/docker.ts';
import { Modal } from './Modal.tsx';

const verbs: Record<DockerActionName, string> = { start: 'Start', stop: 'Stop', restart: 'Restart' };

const effects: Record<DockerActionName, string> = {
  start: 'The engine starts the container.',
  stop:
    'The engine asks the container to stop and kills it if it has not within 10 seconds. What it serves is down until it is started again.',
  restart: 'The engine stops the container and starts it again. What it serves is down meanwhile.',
};

/** Confirms a container action, then carries it out. */
export function DockerActionDialog({
  deviceId,
  container,
  action,
  onClose,
}: {
  deviceId: string;
  container: DockerContainer;
  action: DockerActionName;
  onClose: () => void;
}) {
  const act = useDockerAction(deviceId);

  return (
    <Modal className="dialog" labelledBy="docker-action-title" onClose={onClose}>
      <header className="dialog-head">
        <div>
          <h2 id="docker-action-title">
            {verbs[action]} {container.name}
          </h2>
          <p className="muted small">
            {container.image} · {container.status || container.state}
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
          act.mutate({ action, container: container.name });
        }}
      >
        <section className="plan" aria-label="What this does">
          <div className="plan-head">
            <span className="muted small">What this does</span>
            <span className="pill pill-ok">safe</span>
          </div>
          <p>{effects[action]}</p>
        </section>

        {act.isError ? (
          <div className="error-box" role="alert">
            {act.error.message}
          </div>
        ) : null}
        {act.isSuccess ? (
          <div className="ok-box" role="status">
            Done. The list shows its new state.
          </div>
        ) : null}
        {act.isPending ? (
          <p className="muted small" role="status">
            Waiting for an answer. If policy holds this action, approve it on the Approvals page.
          </p>
        ) : null}

        <div className="form-actions">
          <button className="btn btn-ghost" type="button" onClick={onClose}>
            {act.isSuccess ? 'Close' : 'Cancel'}
          </button>
          {act.isSuccess ? null : (
            <button className="btn btn-primary" type="submit" disabled={act.isPending}>
              {act.isPending ? `${verbs[action]}…` : verbs[action]}
            </button>
          )}
        </div>
      </form>
    </Modal>
  );
}
