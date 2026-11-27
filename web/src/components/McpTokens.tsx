import { useState } from 'react';
import {
  useCreateMcpToken,
  useMcpTokens,
  useRevokeMcpToken,
  type CreatedMcpToken,
  type McpScope,
  type McpToken,
} from '../api/admin.ts';
import { useShareOrigin } from '../api/hooks.ts';
import { formatDateTime } from '../format.ts';
import { Command } from './AddDeviceDialog.tsx';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import { Modal } from './Modal.tsx';

const scopes: { value: McpScope; label: string }[] = [
  { value: 'read', label: 'read: list and read devices, metrics, Kubernetes, pod logs' },
  { value: 'safe', label: 'safe: also restart services and act on Kubernetes' },
  { value: 'dangerous', label: 'dangerous: also run commands and apply automations' },
];

/** The tokens of MCP clients, as `hearth mcp token` manages them (docs/mcp.md). */
export function McpTokens() {
  const tokens = useMcpTokens();
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<McpToken | null>(null);
  const list = tokens.data ?? [];

  return (
    <section className="panel-card" aria-labelledby="mcp-tokens-title">
      <div className="panel-card-head">
        <h2 id="mcp-tokens-title">MCP tokens</h2>
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
        Each AI assistant gets its own token: it is the actor <code>mcp/&lt;name&gt;</code> in policy and the audit log,
        and its scope is the highest class of action it may request. Creating and revoking ask for your password.
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
            <li key={t.name}>
              <span className={`pill ${t.revoked_at ? 'pill-muted' : 'pill-ok'}`}>{t.revoked_at ? 'revoked' : 'active'}</span>
              <strong className="mono">{t.name}</strong>
              <span className={`pill ${t.scope === 'dangerous' ? 'pill-bad' : t.scope === 'safe' ? 'pill-warn' : 'pill-muted'}`}>
                {t.scope}
              </span>
              <span className="small muted">
                created {formatDateTime(t.created_at)}
                {t.revoked_at ? `, revoked ${formatDateTime(t.revoked_at)}` : ''}
              </span>
              {t.revoked_at ? null : (
                <button
                  className="btn btn-small btn-ghost"
                  type="button"
                  onClick={() => {
                    setRevoking(t);
                  }}
                >
                  Revoke
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {creating ? (
        <CreateDialog
          onClose={() => {
            setCreating(false);
          }}
        />
      ) : null}
      {revoking ? (
        <RevokeDialog
          token={revoking}
          onClose={() => {
            setRevoking(null);
          }}
        />
      ) : null}
    </section>
  );
}

function RevokeDialog({ token, onClose }: { token: McpToken; onClose: () => void }) {
  const revoke = useRevokeMcpToken();
  return (
    <ConfirmDialog
      title={`Revoke ${token.name}`}
      actionClass="safe"
      confirmLabel="Revoke"
      pendingLabel="Revoking…"
      pending={revoke.isPending}
      error={revoke.isError ? revoke.error.message : undefined}
      done={revoke.isSuccess ? <>Revoked. The hub refuses the token from its next request.</> : undefined}
      asksPassword
      onConfirm={() => {
        revoke.mutate(token.name);
      }}
      onClose={onClose}
    >
      <p>
        The client using <strong className="mono">{token.name}</strong> loses access at its next request. Its name is
        never reused.
      </p>
    </ConfirmDialog>
  );
}

function CreateDialog({ onClose }: { onClose: () => void }) {
  const create = useCreateMcpToken();
  const [name, setName] = useState('claude');
  const [scope, setScope] = useState<McpScope>('safe');
  const [created, setCreated] = useState<CreatedMcpToken | null>(null);
  const hub = useShareOrigin();

  return (
    <Modal className="dialog dialog-wide" labelledBy="mcp-token-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="mcp-token-title">New MCP token</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      {created ? (
        <>
          <div className="notice" role="status">
            <strong>Copy the token now: it is shown only this once.</strong>
            <span>
              The hub keeps only its hash. Scope <code>{created.scope}</code>; revoke it here when the client no longer
              needs it.
            </span>
          </div>
          <Command label="Token" value={created.secret} />
          {hub ? (
            <Command
              label="Claude Code, over HTTP"
              value={`claude mcp add --transport http hearth ${hub}${created.path} --header "Authorization: Bearer ${created.secret}"`}
            />
          ) : null}
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
            create.mutate({ name, scope }, { onSuccess: setCreated });
          }}
        >
          <section className="plan" aria-label="What this does">
            <div className="plan-head">
              <span className="muted small">What this does</span>
              <span className="pill pill-bad">dangerous</span>
            </div>
            <p>
              Creates a credential an MCP client uses to act on the homelab, up to its scope, through policy. Dangerous
              actions of MCP clients are still held for approval by default.
            </p>
          </section>
          <label className="field">
            Name
            <input
              value={name}
              maxLength={64}
              required
              pattern="[a-z0-9][a-z0-9_.\-]*"
              title="lowercase letters, digits, ., - or _, starting with a letter or digit"
              onChange={(e) => {
                setName(e.target.value);
              }}
            />
          </label>
          <label className="field">
            Scope
            <select
              value={scope}
              onChange={(e) => {
                setScope(e.target.value as McpScope);
              }}
            >
              {scopes.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </label>
          <p className="muted small">You will be asked for the admin password, unless you entered it in the last few minutes.</p>
          {create.isError ? (
            <p className="error" role="alert">
              {create.error.message}
            </p>
          ) : null}
          <div className="form-actions">
            <button className="btn btn-ghost" type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="btn btn-danger" type="submit" disabled={create.isPending}>
              {create.isPending ? 'Creating…' : 'Create token'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
