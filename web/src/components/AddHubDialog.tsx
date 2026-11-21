import { useState } from 'react';
import { ApiError } from '../api/client.ts';
import { useCreateJoinToken } from '../api/cluster.ts';
import { refusalMessage, type ClusterRole } from '../cluster.ts';
import { Command } from './AddDeviceDialog.tsx';
import { Modal } from './Modal.tsx';

const ttls = [
  { value: '15m', label: '15 minutes' },
  { value: '1h', label: '1 hour' },
  { value: '6h', label: '6 hours' },
  { value: '24h', label: '24 hours' },
];

const allRoles: { role: ClusterRole; label: string }[] = [
  { role: 'storage', label: 'storage' },
  { role: 'master', label: 'master (receives the CA key)' },
];

/**
 * Creates a cluster join token for a new hub, once confirmed and with the
 * password again, and shows it once with the command that uses it.
 */
export function AddHubDialog({ onClose }: { onClose: () => void }) {
  const create = useCreateJoinToken();
  const [ttl, setTtl] = useState('15m');
  const [roles, setRoles] = useState<ClusterRole[]>(['storage', 'master']);
  const tok = create.data;
  const err = create.error;

  return (
    <Modal className="dialog" labelledBy="add-hub-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="add-hub-title">Add a hub</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>

      {tok ? (
        <div className="form">
          <Command label="On the new hub, with an empty data dir" value={tok.join_command} />
          <p className="muted small">
            Single use · expires at{' '}
            {new Date(tok.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} · joins through
            this master ({tok.hub_url})
          </p>
          <div className="notice">
            Shown once: the token cannot be shown again. Copy the command now; anyone who has it can join a hub to this
            cluster until it is used or expires.
          </div>
          <p className="muted small">
            The other hubs reach the new one at its hostname on port 7444; add <code>--cluster-advertise host:port</code>{' '}
            if they cannot. It appears in the members above once it has joined.
          </p>
          <div className="form-actions">
            <button className="btn btn-primary" type="button" onClick={onClose}>
              Done
            </button>
          </div>
        </div>
      ) : (
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate({ ttl, roles });
          }}
        >
          <p className="muted">
            Creates a single-use join token and the command that runs a new hub with it. The new hub joins through this
            master.
          </p>
          <label className="field">
            Token expires after
            <select
              value={ttl}
              onChange={(e) => {
                setTtl(e.target.value);
              }}
            >
              {ttls.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </label>
          <fieldset className="field join-roles">
            <legend>Roles the token grants the new hub</legend>
            <div className="join-roles-options">
              {allRoles.map(({ role, label }) => (
                <label key={role}>
                  <input
                    type="checkbox"
                    checked={roles.includes(role)}
                    onChange={(e) => {
                      setRoles(e.target.checked ? [...roles, role] : roles.filter((r) => r !== role));
                    }}
                  />
                  {label}
                </label>
              ))}
            </div>
          </fieldset>

          <section className="plan" aria-label="What this does">
            <div className="plan-head">
              <span className="muted small">What this does</span>
              <span className="pill pill-bad">dangerous</span>
            </div>
            {roles.includes('master') ? (
              <p>
                A hub that joins with this token as a master receives the hub CA&apos;s private key: it can then issue
                certificates every hub and agent trusts. Treat the token like the CA key itself.
              </p>
            ) : (
              <p>
                The new hub joins as a storage member only: it never receives the hub CA&apos;s private key, whatever it
                asks for. It can still hold a copy of the cluster&apos;s data.
              </p>
            )}
            <p>
              The token is bound to these roles: the new hub takes at most them, and only those its own{' '}
              <code>--allow-roles</code> allow too.
            </p>
          </section>

          {err ? (
            <div className="error-box" role="alert">
              {err instanceof ApiError ? refusalMessage(err.code, err.message) : err.message}
            </div>
          ) : null}
          {create.isPending ? (
            <p className="muted small" role="status">
              Waiting for an answer. If policy holds this action, approve it on the Approvals page.
            </p>
          ) : null}

          <div className="form-actions">
            <button className="btn btn-ghost" type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="btn btn-danger" type="submit" disabled={create.isPending || roles.length === 0}>
              {create.isPending ? 'Creating…' : 'Create join token'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
