import { useState, type SubmitEvent } from 'react';
import { ApiError } from '../api/client.ts';
import { useLogin } from '../api/hooks.ts';
import { Logo } from './Logo.tsx';

export function Login() {
  const [password, setPassword] = useState('');
  const login = useLogin();

  const submit = (e: SubmitEvent) => {
    e.preventDefault();
    login.mutate(password);
  };

  const err = login.error;
  const notSet = err instanceof ApiError && err.code === 'password_not_set';

  return (
    <main className="login">
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">
          <Logo size={36} />
          <h1>Hearth</h1>
        </div>
        <p className="muted">Sign in to your homelab.</p>
        {notSet ? (
          <div className="notice" role="alert">
            <strong>No admin password yet.</strong>
            <p>Set one on the hub host, then sign in:</p>
            <pre>
              <code>hearth admin set-password</code>
            </pre>
            <p className="muted small">
              Or restart the hub with <code>HEARTH_ADMIN_PASSWORD</code> set.
            </p>
          </div>
        ) : null}
        <label className="field">
          <span>Admin password</span>
          <input
            type="password"
            autoComplete="current-password"
            autoFocus
            required
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
            }}
            aria-invalid={err instanceof ApiError && err.code === 'bad_credentials'}
          />
        </label>
        {err && !notSet ? (
          <p className="error" role="alert">
            {err instanceof ApiError && err.code === 'bad_credentials' ? 'Wrong password.' : err.message}
          </p>
        ) : null}
        <button className="btn btn-primary" type="submit" disabled={login.isPending || password === ''}>
          {login.isPending ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}
