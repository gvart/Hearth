import type { ReactNode } from 'react';
import { Modal } from './Modal.tsx';

interface Props {
  title: string;
  /** The action's policy class, shown as a pill. */
  actionClass: 'safe' | 'dangerous';
  /** What the action does, in plain words. */
  children: ReactNode;
  confirmLabel: string;
  pendingLabel: string;
  pending: boolean;
  error?: string;
  /** Shown instead of the form once the action is done. */
  done?: ReactNode;
  /** The admin password is asked for next. */
  asksPassword?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}

/** Confirms an action of the web UI before it is sent, and shows how it ended. */
export function ConfirmDialog({
  title,
  actionClass,
  children,
  confirmLabel,
  pendingLabel,
  pending,
  error,
  done,
  asksPassword,
  onConfirm,
  onClose,
}: Props) {
  return (
    <Modal className="dialog" labelledBy="confirm-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="confirm-title">{title}</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      {done ? (
        <>
          <div className="ok-box" role="status">
            {done}
          </div>
          <div className="form-actions">
            <button className="btn btn-primary" type="button" onClick={onClose}>
              Close
            </button>
          </div>
        </>
      ) : (
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            onConfirm();
          }}
        >
          <section className="plan" aria-label="What this does">
            <div className="plan-head">
              <span className="muted small">What this does</span>
              <span className={`pill ${actionClass === 'dangerous' ? 'pill-bad' : 'pill-ok'}`}>{actionClass}</span>
            </div>
            {children}
          </section>
          {asksPassword ? (
            <p className="muted small">You will be asked for the admin password, unless you entered it in the last few minutes.</p>
          ) : null}
          {error ? (
            <div className="error-box" role="alert">
              {error}
            </div>
          ) : null}
          {pending ? (
            <p className="muted small" role="status">
              Waiting for an answer. If policy holds this action, approve it on the Approvals page.
            </p>
          ) : null}
          <div className="form-actions">
            <button className="btn btn-ghost" type="button" onClick={onClose}>
              Cancel
            </button>
            <button
              className={`btn ${actionClass === 'dangerous' ? 'btn-danger' : 'btn-primary'}`}
              type="submit"
              disabled={pending}
            >
              {pending ? pendingLabel : confirmLabel}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
