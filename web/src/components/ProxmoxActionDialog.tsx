import { useProxmoxAction, type ProxmoxActionName, type ProxmoxGuest, type ProxmoxServer } from '../api/proxmox.ts';
import { Modal } from './Modal.tsx';

const verbs: Record<ProxmoxActionName, string> = { start: 'Start', stop: 'Stop', reboot: 'Reboot' };

const effects: Record<ProxmoxActionName, string> = {
  start: 'Proxmox starts the guest.',
  stop: 'Proxmox stops the guest at once, like pulling the power plug. Unsaved data inside it can be lost.',
  reboot: 'Proxmox shuts the guest down and starts it again. What it serves is down until it is back.',
};

/** Confirms a guest action, then carries it out. */
export function ProxmoxActionDialog({
  server,
  guest,
  action,
  actionClass,
  onClose,
}: {
  server: ProxmoxServer;
  guest: ProxmoxGuest;
  action: ProxmoxActionName;
  actionClass: string;
  onClose: () => void;
}) {
  const act = useProxmoxAction(server.id);
  const dangerous = actionClass === 'dangerous';
  const name = guest.name || String(guest.vmid);

  return (
    <Modal className="dialog" labelledBy="pve-action-title" onClose={onClose}>
      <header className="dialog-head">
        <div>
          <h2 id="pve-action-title">
            {verbs[action]} {name}
          </h2>
          <p className="muted small">
            {guest.kind === 'qemu' ? 'VM' : 'LXC'} {guest.vmid} on {guest.node} · {server.name}
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
          act.mutate({ action, vmid: guest.vmid });
        }}
      >
        <section className="plan" aria-label="What this does">
          <div className="plan-head">
            <span className="muted small">What this does</span>
            <span className={`pill pill-${dangerous ? 'bad' : 'ok'}`}>{actionClass}</span>
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
            {act.data.result}. Its status updates here shortly.
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
            <button className={`btn ${dangerous ? 'btn-danger' : 'btn-primary'}`} type="submit" disabled={act.isPending}>
              {act.isPending ? `${verbs[action]}…` : verbs[action]}
            </button>
          )}
        </div>
      </form>
    </Modal>
  );
}
