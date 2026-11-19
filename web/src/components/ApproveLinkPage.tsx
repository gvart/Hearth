import { useEffect, useState } from 'react';
import { ApiError } from '../api/client.ts';
import { useApprovalLink, useDenyApprovalLink } from '../api/hooks.ts';
import { timeLeft } from '../format.ts';
import { ApprovalDetails, StatusPill } from './ApprovalsPage.tsx';
import { Logo } from './Logo.tsx';

/** The current time, ticking every second while mounted. */
function useNow(): number {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const t = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => {
      clearInterval(t);
    };
  }, []);
  return now;
}

/**
 * The page an approval link opens (#/approve/<token>), with no session: the
 * link is the credential for its one approval. Opening it only shows the
 * action; a tap denies it, which spends the link. A link cannot approve:
 * that takes a signed-in approver and their password.
 */
export function ApproveLinkPage({ token }: { token: string }) {
  const link = useApprovalLink(token);
  const decide = useDenyApprovalLink(token);
  const now = useNow();

  const invalid =
    (link.error instanceof ApiError && link.error.code === 'link_invalid') ||
    (decide.error instanceof ApiError && decide.error.code === 'link_invalid');
  const ap = link.data;

  let body;
  if (link.isPending) {
    body = <p className="muted">Loading…</p>;
  } else if (invalid) {
    body = (
      <div className="error-box" role="alert">
        This approval link is invalid, already used or expired. Open Hearth to see the approval.
      </div>
    );
  } else if (link.isError) {
    body = (
      <div className="error-box" role="alert">
        Cannot reach the hub: {link.error.message}
      </div>
    );
  } else if (decide.isSuccess) {
    body = (
      <div className="notice" role="status">
        <strong>Denied.</strong>
        <p>The action will not run. This link is used up.</p>
      </div>
    );
  } else if (ap) {
    const open = ap.status === 'pending' && timeLeft(ap.expires_at, now) !== 'expired';
    body = (
      <>
        <ApprovalDetails approval={ap} />
        {open ? (
          <>
            <p className="muted small">
              Expires in {timeLeft(ap.expires_at, now)}; unanswered, it is denied. The link works once.
            </p>
            {decide.isError ? (
              <p className="error" role="alert">
                {decide.error.message}
              </p>
            ) : null}
            <div className="approval-actions">
              <button
                className="btn"
                type="button"
                disabled={decide.isPending}
                onClick={() => {
                  decide.mutate();
                }}
              >
                Deny
              </button>
              <a className="btn btn-primary" href="#/approvals">
                Sign in to approve
              </a>
            </div>
            <p className="muted small">
              This link can only deny. Approving takes your password: sign in to Hearth and approve it on the
              Approvals page.
            </p>
          </>
        ) : (
          <p>
            This approval is <StatusPill status={ap.status === 'pending' ? 'expired' : ap.status} />
            {ap.decided_by ? ` by ${ap.decided_by}` : ''}.
          </p>
        )}
      </>
    );
  }

  return (
    <main className="login">
      <div className="login-card approve-card">
        <div className="login-brand">
          <Logo size={32} />
          <h1>Approval requested</h1>
        </div>
        {body}
      </div>
    </main>
  );
}
