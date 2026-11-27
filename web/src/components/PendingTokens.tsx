import { useState } from 'react';
import type { PendingToken } from '../api/client.ts';
import { usePendingTokens, useRevokeToken } from '../api/hooks.ts';
import { relativeTime } from '../format.ts';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import { Tip } from './Tip.tsx';

/**
 * The enrollment tokens no device has used yet, as `hearth token list` shows
 * them, each with Revoke. Renders nothing when there are none.
 */
export function PendingTokens({ now }: { now: number }) {
  const q = usePendingTokens();
  const [revoking, setRevoking] = useState<PendingToken | null>(null);
  if (q.isError) {
    return (
      <section className="unmanaged" aria-labelledby="tokens-title">
        <div className="section-head">
          <h2 id="tokens-title">Unused enrollment tokens</h2>
        </div>
        <div className="error-box" role="alert">
          Could not load enrollment tokens: {q.error.message}
        </div>
      </section>
    );
  }
  const list = q.data ?? [];
  if (list.length === 0) {
    return null;
  }
  return (
    <section className="unmanaged" aria-labelledby="tokens-title">
      <div className="section-head">
        <h2 id="tokens-title">
          Unused enrollment tokens <Tip id="tokens" />
        </h2>
        <p className="muted">
          {String(list.length)} waiting for a device
        </p>
      </div>
      <div className="table-wrap">
        <table className="devices network">
          <thead>
            <tr>
              <th>Token</th>
              <th>Device name</th>
              <th>Labels</th>
              <th>Expires</th>
              <th>
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {list.map((t) => (
              <tr key={t.id}>
                <td>
                  <span className="name-cell">
                    <span className="mono">{t.id}</span>
                    {t.hub ? (
                      <span className="badge" title="A capable device that enrolls with it may become a hub">
                        hub-eligible
                      </span>
                    ) : null}
                  </span>
                </td>
                <td>{t.name ?? <span className="muted">its hostname</span>}</td>
                <td className="mono small">
                  {Object.entries(t.labels)
                    .map(([k, v]) => `${k}=${v}`)
                    .join(', ') || <span className="muted">—</span>}
                </td>
                <td className="muted" title={t.expires_at}>
                  {relativeTime(t.expires_at, now)}
                </td>
                <td>
                  <button
                    className="btn btn-small btn-ghost"
                    type="button"
                    onClick={() => {
                      setRevoking(t);
                    }}
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
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

function RevokeDialog({ token, onClose }: { token: PendingToken; onClose: () => void }) {
  const revoke = useRevokeToken();
  return (
    <ConfirmDialog
      title={`Revoke token ${token.id}`}
      actionClass="safe"
      confirmLabel="Revoke"
      pendingLabel="Revoking…"
      pending={revoke.isPending}
      error={revoke.isError ? revoke.error.message : undefined}
      done={revoke.isSuccess ? <>Revoked. No device can enroll with this token.</> : undefined}
      asksPassword={token.hub}
      onConfirm={() => {
        revoke.mutate(token);
      }}
      onClose={onClose}
    >
      <p>
        No device can enroll with <strong className="mono">{token.id}</strong> any more
        {token.hub ? ', so none can become a hub with it' : ''}. An install command that names it fails.
      </p>
    </ConfirmDialog>
  );
}
