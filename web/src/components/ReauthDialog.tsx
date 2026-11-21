import { useMutation } from '@tanstack/react-query';
import { useState } from 'react';
import { ApiError } from '../api/client.ts';
import { reauthenticate, settleReauthPrompt, useReauthPrompt, useRememberReauth } from '../api/reauth.ts';
import { Modal } from './Modal.tsx';

/**
 * Asks for the admin password before a sensitive action, whenever one waits
 * for it (see useWithReauth). Rendered once, by the Shell.
 */
export function ReauthHost() {
  const pending = useReauthPrompt();
  return pending ? <ReauthDialog key="reauth" /> : null;
}

function ReauthDialog() {
  const [password, setPassword] = useState('');
  const remember = useRememberReauth();
  const check = useMutation({
    mutationFn: reauthenticate,
    onSuccess: (r) => {
      remember(r);
      settleReauthPrompt(true);
    },
    onError: () => {
      setPassword('');
    },
  });
  const wrong = check.error instanceof ApiError && check.error.code === 'reauth_failed';

  return (
    <Modal
      className="dialog"
      labelledBy="reauth-title"
      onClose={() => {
        if (!check.isSuccess) {
          settleReauthPrompt(false);
        }
      }}
    >
      <header className="dialog-head">
        <h2 id="reauth-title">Confirm it is you</h2>
      </header>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          check.mutate(password);
        }}
      >
        <p className="muted small">
          This action is sensitive: enter the admin password again. It covers sensitive actions for the next five
          minutes, in this session only.
        </p>
        <label className="field">
          Admin password
          <input
            type="password"
            autoComplete="current-password"
            autoFocus
            required
            value={password}
            aria-invalid={wrong}
            onChange={(e) => {
              setPassword(e.target.value);
            }}
          />
        </label>
        {check.isError ? (
          <p className="error" role="alert">
            {wrong ? 'Wrong password.' : check.error.message}
          </p>
        ) : null}
        <div className="form-actions">
          <button
            className="btn btn-ghost"
            type="button"
            onClick={() => {
              settleReauthPrompt(false);
            }}
          >
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" disabled={check.isPending || password === ''}>
            {check.isPending ? 'Checking…' : 'Confirm'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
