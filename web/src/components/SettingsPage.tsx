import { useState } from 'react';
import type { AutomationProblem } from '../api/automations.ts';
import {
  problemsOf,
  useChangePassword,
  useDownloadBackup,
  usePolicy,
  useSavePolicy,
  useValidatePolicy,
  type Validation,
} from '../api/admin.ts';
import { ApiError } from '../api/client.ts';
import { useSession } from '../api/hooks.ts';
import { chooseTheme, storedTheme, themes, type Theme } from '../theme.ts';
import { McpTokens } from './McpTokens.tsx';
import { Modal } from './Modal.tsx';
import './PanelsPage.css';
import './SettingsPage.css';

/** The hub's own settings: version, password, MCP tokens, policy and backups. */
export function SettingsPage() {
  const session = useSession();
  return (
    <main className="content">
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p className="muted">
            Hearth {session.data?.version ?? ''} · what <code>hearth</code> does on the hub host, behind your session.
          </p>
        </div>
      </div>
      <div className="settings">
        <AppearanceCard />
        <PolicyCard />
        <McpTokens />
        <BackupCard />
        <PasswordCard />
      </div>
    </main>
  );
}

/** Picks the theme, for this browser. */
function AppearanceCard() {
  const [theme, setTheme] = useState<Theme>(storedTheme);
  return (
    <section className="panel-card" aria-labelledby="appearance-title">
      <div className="panel-card-head">
        <h2 id="appearance-title">Appearance</h2>
        <div className="range-picker theme-picker" role="group" aria-label="Theme">
          {themes.map((t) => (
            <button
              key={t.id}
              type="button"
              className="range-option"
              aria-pressed={theme === t.id}
              onClick={() => {
                chooseTheme(t.id);
                setTheme(t.id);
              }}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>
      <p className="muted small">{themes.find((t) => t.id === theme)?.hint} Remembered in this browser.</p>
    </section>
  );
}

export function ProblemList({ problems }: { problems: AutomationProblem[] }) {
  return (
    <ul className="problem-list">
      {problems.map((p) => (
        <li key={`${String(p.line)}:${p.message}`}>
          {p.line > 0 ? `Line ${String(p.line)}: ` : ''}
          {p.message}
        </li>
      ))}
    </ul>
  );
}

/** policy.yaml: read-only for anyone signed in, editable behind the password again. */
function PolicyCard() {
  const policy = usePolicy();
  const [editing, setEditing] = useState(false);
  return (
    <section className="panel-card" aria-labelledby="policy-title">
      <div className="panel-card-head">
        <h2 id="policy-title">Policy</h2>
        <div className="row-actions">
          <button
            className="btn btn-small"
            type="button"
            disabled={!policy.data}
            onClick={() => {
              setEditing(true);
            }}
          >
            Edit policy
          </button>
        </div>
      </div>
      <p className="muted small">
        <code>policy.yaml</code> decides every action: <code>allow</code>, hold for approval (<code>confirm</code>) or{' '}
        <code>deny</code>, per class and actor kind. Empty means the defaults: everything allowed, except dangerous
        actions of automations (denied) and of MCP clients (held).
      </p>
      {policy.isError ? (
        <p className="error" role="alert">
          {policy.error instanceof ApiError && policy.error.status === 404
            ? 'This hub keeps its configuration in files: upgrade every hub of the cluster to edit it here.'
            : `Could not load the policy: ${policy.error.message}`}
        </p>
      ) : policy.data ? (
        <label className="field">
          <span className="sr-only">policy.yaml</span>
          <textarea
            className="doc-yaml"
            readOnly
            value={policy.data.yaml || '# empty: the built-in defaults'}
            rows={Math.min(16, Math.max(4, policy.data.yaml.split('\n').length + 1))}
            wrap="off"
          />
        </label>
      ) : (
        <p className="muted small">Loading…</p>
      )}
      {editing && policy.data ? (
        <PolicyEditor
          initial={policy.data.yaml}
          revision={policy.data.revision}
          onClose={() => {
            setEditing(false);
          }}
        />
      ) : null}
    </section>
  );
}

function PolicyEditor({ initial, revision, onClose }: { initial: string; revision: string; onClose: () => void }) {
  const [yaml, setYaml] = useState(initial);
  const [checked, setChecked] = useState<Validation | null>(null);
  const [confirming, setConfirming] = useState(false);
  const validate = useValidatePolicy();
  const save = useSavePolicy();
  const problems = checked && !checked.valid ? checked.problems : problemsOf(save.error);

  return (
    <Modal className="dialog dialog-wide" labelledBy="policy-edit-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="policy-edit-title">Edit policy.yaml</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      {save.isSuccess ? (
        <>
          <div className="ok-box" role="status">
            Saved. Every hub applies the new policy within seconds.
          </div>
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
            validate.mutate(yaml, {
              onSuccess: (v) => {
                setChecked(v);
                setConfirming(v.valid);
              },
            });
          }}
        >
          <label className="field">
            policy.yaml
            <textarea
              className="doc-yaml"
              value={yaml}
              rows={Math.min(24, Math.max(10, yaml.split('\n').length + 2))}
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              wrap="off"
              aria-invalid={problems.length > 0}
              onChange={(e) => {
                setYaml(e.target.value);
                setChecked(null);
                setConfirming(false);
                save.reset();
              }}
            />
          </label>
          <p className="muted small">
            Saving is <code>config.import</code>, a dangerous action: it is checked first, as a whole with the rest of
            the configuration, and asks for your password. A policy that would deny it to you here, or to the admin on
            the hub host, is refused.
          </p>
          {problems.length > 0 ? (
            <div className="error-box" role="alert">
              <strong>Not valid</strong>
              <ProblemList problems={problems} />
            </div>
          ) : null}
          {validate.isError ? (
            <p className="error" role="alert">
              {validate.error.message}
            </p>
          ) : null}
          {save.isError && problemsOf(save.error).length === 0 ? (
            <div className="error-box" role="alert">
              Not saved: {save.error.message}
            </div>
          ) : null}
          {confirming ? (
            <div className="notice" role="status">
              <strong>The policy is valid. Save it?</strong>
              <span>It decides every action of every client, on every hub, from the moment it is applied.</span>
              {save.isPending ? (
                <span className="muted small">Saving. If policy holds this for approval, approve it on the Approvals page.</span>
              ) : null}
              <div className="settings-actions">
                <button
                  className="btn btn-danger"
                  type="button"
                  disabled={save.isPending}
                  onClick={() => {
                    save.mutate({ yaml, revision });
                  }}
                >
                  {save.isPending ? 'Saving…' : 'Save policy'}
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
          <div className="form-actions">
            <button className="btn btn-ghost" type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="btn btn-primary" type="submit" disabled={validate.isPending || confirming}>
              {validate.isPending ? 'Checking…' : 'Check and save…'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}

/** Downloads an encrypted backup, as `hearth backup` writes it. */
function BackupCard() {
  const [open, setOpen] = useState(false);
  return (
    <section className="panel-card" aria-labelledby="backup-title">
      <div className="panel-card-head">
        <h2 id="backup-title">Backup</h2>
        <div className="row-actions">
          <button
            className="btn btn-small"
            type="button"
            onClick={() => {
              setOpen(true);
            }}
          >
            Download backup…
          </button>
        </div>
      </div>
      <p className="muted small">
        An encrypted archive of the hub&apos;s CA (its private key included), database and configuration, the file{' '}
        <code>hearth backup</code> writes. Restore it with <code>hearth restore</code> on a hub host.
      </p>
      {open ? (
        <BackupDialog
          onClose={() => {
            setOpen(false);
          }}
        />
      ) : null}
    </section>
  );
}

const minPassphrase = 12;

function BackupDialog({ onClose }: { onClose: () => void }) {
  const [passphrase, setPassphrase] = useState('');
  const [again, setAgain] = useState('');
  const download = useDownloadBackup();
  const mismatch = again !== '' && again !== passphrase;
  const short = passphrase.length > 0 && passphrase.length < minPassphrase;

  return (
    <Modal className="dialog" labelledBy="backup-dialog-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="backup-dialog-title">Download a backup</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      {download.isSuccess ? (
        <>
          <div className="ok-box" role="status">
            {download.data} is downloading. Keep it and its passphrase safe and apart: it holds the hub&apos;s CA key,
            and cannot be restored without the passphrase.
          </div>
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
            download.mutate(passphrase);
          }}
        >
          <section className="plan" aria-label="What this does">
            <div className="plan-head">
              <span className="muted small">What this does</span>
              <span className="pill pill-bad">dangerous</span>
            </div>
            <p>
              The hub writes an encrypted backup, with its CA private key and every credential it holds, and sends it to
              this browser. It is audited as <code>hub.backup</code> and asks for your password.
            </p>
          </section>
          <label className="field">
            Passphrase
            <input
              type="password"
              autoComplete="new-password"
              required
              minLength={minPassphrase}
              value={passphrase}
              aria-invalid={short}
              onChange={(e) => {
                setPassphrase(e.target.value);
              }}
            />
            <span className="muted small">
              At least {minPassphrase} characters. Without it the backup cannot be restored.
            </span>
          </label>
          <label className="field">
            Repeat the passphrase
            <input
              type="password"
              autoComplete="new-password"
              required
              value={again}
              aria-invalid={mismatch}
              onChange={(e) => {
                setAgain(e.target.value);
              }}
            />
          </label>
          {mismatch ? <p className="error">The passphrases do not match.</p> : null}
          {download.isError ? (
            <div className="error-box" role="alert">
              {download.error.message}
            </div>
          ) : null}
          {download.isPending ? (
            <p className="muted small" role="status">
              Writing the backup. If policy holds this action, approve it on the Approvals page.
            </p>
          ) : null}
          <div className="form-actions">
            <button className="btn btn-ghost" type="button" onClick={onClose}>
              Cancel
            </button>
            <button
              className="btn btn-danger"
              type="submit"
              disabled={download.isPending || short || passphrase === '' || again !== passphrase}
            >
              {download.isPending ? 'Writing…' : 'Download'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}

/** Changes the admin password, given the current one. */
function PasswordCard() {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [again, setAgain] = useState('');
  const change = useChangePassword();
  const mismatch = again !== '' && again !== next;
  const wrong = change.error instanceof ApiError && change.error.code === 'reauth_failed';

  return (
    <section className="panel-card" aria-labelledby="password-title">
      <h2 id="password-title">Admin password</h2>
      <p className="muted small">
        Changing it signs out every session, this one too. A lost password is reset on the hub host with{' '}
        <code>hearth admin set-password</code>.
      </p>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate({ current, next });
        }}
      >
        <label className="field">
          Current password
          <input
            type="password"
            autoComplete="current-password"
            required
            value={current}
            aria-invalid={wrong}
            onChange={(e) => {
              setCurrent(e.target.value);
            }}
          />
        </label>
        <label className="field">
          New password
          <input
            type="password"
            autoComplete="new-password"
            required
            minLength={8}
            value={next}
            onChange={(e) => {
              setNext(e.target.value);
            }}
          />
        </label>
        <label className="field">
          Repeat the new password
          <input
            type="password"
            autoComplete="new-password"
            required
            value={again}
            aria-invalid={mismatch}
            onChange={(e) => {
              setAgain(e.target.value);
            }}
          />
        </label>
        {mismatch ? <p className="error">The new passwords do not match.</p> : null}
        {change.isError ? (
          <p className="error" role="alert">
            {wrong ? 'The current password is wrong.' : change.error.message}
          </p>
        ) : null}
        <div className="settings-actions">
          <button
            className="btn btn-primary"
            type="submit"
            disabled={change.isPending || next.length < 8 || next !== again || current === ''}
          >
            {change.isPending ? 'Changing…' : 'Change password'}
          </button>
        </div>
      </form>
    </section>
  );
}
