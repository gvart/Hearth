import { useState } from 'react';
import type { CreatedDashboardToken } from '../api/client.ts';
import { useCreateDashboardToken, useDashboardTokens, useRevokeDashboardToken, useShareOrigin } from '../api/hooks.ts';
import { homepageSnippet } from '../dashboard.ts';
import { formatDateTime } from '../format.ts';
import { linkExpiries } from '../panels.ts';
import { Command } from './AddDeviceDialog.tsx';
import { Modal } from './Modal.tsx';

/**
 * Read-only tokens for dashboards such as Homepage: each reads device counts
 * and states, and nothing else (docs/homepage.md).
 */
export function DashboardTokens() {
  const tokens = useDashboardTokens();
  const revoke = useRevokeDashboardToken();
  const [creating, setCreating] = useState(false);
  const list = tokens.data ?? [];

  return (
    <section className="panel-card" aria-labelledby="dashboard-tokens-title">
      <div className="panel-card-head">
        <h2 id="dashboard-tokens-title">Dashboard tokens</h2>
        <div className="row-actions">
          <button
            className="btn btn-small btn-primary"
            type="button"
            onClick={() => {
              setCreating(true);
            }}
          >
            New token
          </button>
        </div>
      </div>
      <p className="muted small">
        For Homepage and other dashboards: a token reads device counts and states, and nothing else. Each read is
        decided by the hub&apos;s policy (the <code>dashboard</code> actor) and audited.
      </p>
      {tokens.isError ? (
        <p className="error" role="alert">
          Could not load tokens: {tokens.error.message}
        </p>
      ) : list.length === 0 ? (
        <p className="muted small">{tokens.isPending ? 'Loading…' : 'No tokens yet.'}</p>
      ) : (
        <ul className="panel-links">
          {list.map((t) => (
            <li key={t.id}>
              <span className={`pill ${t.status === 'active' ? 'pill-ok' : 'pill-muted'}`}>{t.status}</span>
              <strong>{t.name}</strong>
              <span className="small muted">
                created {formatDateTime(t.created_at)}
                {t.expires_at ? `, expires ${formatDateTime(t.expires_at)}` : ', never expires'}
              </span>
              {t.status === 'active' ? (
                <button
                  className="btn btn-small btn-ghost"
                  type="button"
                  disabled={revoke.isPending}
                  onClick={() => {
                    revoke.mutate(t.id);
                  }}
                >
                  Revoke
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
      {revoke.isError ? (
        <p className="error" role="alert">
          {revoke.error.message}
        </p>
      ) : null}
      {revoke.data ? (
        <p className="notice small" role="status">
          Revoked: {revoke.data.message}.
        </p>
      ) : null}
      {creating ? (
        <CreateDialog
          onClose={() => {
            setCreating(false);
          }}
        />
      ) : null}
    </section>
  );
}

function CreateDialog({ onClose }: { onClose: () => void }) {
  const create = useCreateDashboardToken();
  const [name, setName] = useState('homepage');
  const [expiresIn, setExpiresIn] = useState('');
  const [created, setCreated] = useState<CreatedDashboardToken | null>(null);
  const origin = useShareOrigin();

  return (
    <Modal className="dialog dialog-wide" labelledBy="dashboard-token-title" onClose={onClose}>
      <h2 id="dashboard-token-title">New dashboard token</h2>
      {created ? (
        <>
          <div className="notice" role="status">
            <strong>Copy the token now: it is shown only this once.</strong>
            <span>It reads device counts and states. Revoke it when the dashboard no longer needs it.</span>
          </div>
          <Command label="Token" value={created.secret} />
          {origin ? <Command label="Homepage services.yaml" value={homepageSnippet(origin, created.secret)} /> : null}
          <div className="form-actions">
            <button className="btn btn-primary" type="button" onClick={onClose}>
              Done
            </button>
          </div>
        </>
      ) : (
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate({ name, expiresIn }, { onSuccess: setCreated });
          }}
        >
          <label className="field">
            Name
            <input
              value={name}
              maxLength={100}
              required
              onChange={(e) => {
                setName(e.target.value);
              }}
            />
          </label>
          <label className="field">
            Token lasts
            <select
              value={expiresIn}
              onChange={(e) => {
                setExpiresIn(e.target.value);
              }}
            >
              {linkExpiries.map((x) => (
                <option key={x.value} value={x.value}>
                  {x.label}
                </option>
              ))}
            </select>
          </label>
          {create.isError ? (
            <p className="error" role="alert">
              {create.error.message}
            </p>
          ) : null}
          <div className="form-actions">
            <button className="btn btn-ghost" type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="btn btn-primary" type="submit" disabled={create.isPending}>
              Create token
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
