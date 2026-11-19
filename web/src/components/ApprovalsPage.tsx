import { useEffect, useState } from 'react';
import type { Approval, ApprovalStatus } from '../api/client.ts';
import { useApprovals, useDecideApproval } from '../api/hooks.ts';
import { approvalDetail } from '../automations/session.ts';
import { formatDateTime, relativeTime, timeLeft } from '../format.ts';

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

const statusPill: Record<ApprovalStatus, string> = {
  pending: 'pill-warn',
  approved: 'pill-ok',
  denied: 'pill-bad',
  expired: 'pill-bad',
};

export function StatusPill({ status }: { status: ApprovalStatus }) {
  return <span className={`pill ${statusPill[status]}`}>{status}</span>;
}

/** What a held action is: the action, who asked, its target and detail. */
export function ApprovalDetails({ approval }: { approval: Approval }) {
  const { planText, planWithheld, rest } = approvalDetail(approval.detail);
  const detail = Object.keys(rest).length > 0 ? JSON.stringify(rest, null, 2) : '';
  return (
    <dl className="approval-details">
      <dt>Action</dt>
      <dd>
        <span className="mono">{approval.action}</span>{' '}
        <span className={`pill ${approval.class === 'dangerous' ? 'pill-bad' : 'pill-warn'}`}>{approval.class}</span>
      </dd>
      <dt>Requested by</dt>
      <dd className="mono">
        {approval.actor_kind}/{approval.actor_id}
      </dd>
      {approval.target ? (
        <>
          <dt>Target</dt>
          <dd className="mono">{approval.target}</dd>
        </>
      ) : null}
      {planText ? (
        <>
          <dt>Plan</dt>
          <dd>
            <pre className="approval-detail approval-plan">{planText}</pre>
          </dd>
        </>
      ) : null}
      {planWithheld ? (
        <>
          <dt>Plan</dt>
          <dd>Sign in to Hearth and open Approvals to read what this would do before you decide.</dd>
        </>
      ) : null}
      {detail ? (
        <>
          <dt>Detail</dt>
          <dd>
            <pre className="approval-detail">{detail}</pre>
          </dd>
        </>
      ) : null}
    </dl>
  );
}

/** Pending approvals to decide, and the history of decided ones. */
export function ApprovalsPage() {
  const pending = useApprovals('pending');
  const all = useApprovals('all');
  const now = useNow();
  const list = pending.data ?? [];
  const history = (all.data ?? []).filter((a) => a.status !== 'pending');

  return (
    <main className="content">
      <div className="page-head">
        <div>
          <h1>Approvals</h1>
          {pending.data ? (
            <p className="muted">
              {list.length === 0 ? 'Nothing waiting' : `${String(list.length)} waiting for a decision`}
            </p>
          ) : null}
        </div>
      </div>

      {pending.isError ? (
        <div className="error-box" role="alert">
          Could not load approvals: {pending.error.message}
        </div>
      ) : pending.isPending ? (
        <p className="muted">Loading approvals…</p>
      ) : list.length === 0 ? (
        <div className="empty">
          <h2>No action is waiting</h2>
          <p className="muted">
            Actions the hub&apos;s <code>policy.yaml</code> sets to <code>confirm</code> wait here until someone
            approves them. Unanswered, they are denied when they expire.
          </p>
        </div>
      ) : (
        <div className="approval-list">
          {list.map((a) => (
            <PendingCard key={a.id} approval={a} now={now} />
          ))}
        </div>
      )}

      <h2 className="section-title">History</h2>
      {all.isError ? (
        <div className="error-box" role="alert">
          Could not load the history: {all.error.message}
        </div>
      ) : history.length === 0 ? (
        <p className="muted">{all.isPending ? 'Loading…' : 'No decided approvals yet.'}</p>
      ) : (
        <div className="table-wrap">
          <table className="devices kube">
            <thead>
              <tr>
                <th>Status</th>
                <th>Action</th>
                <th>Target</th>
                <th>Requested by</th>
                <th>Decided by</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {history.map((a) => (
                <tr key={a.id} className="static">
                  <td>
                    <StatusPill status={a.status} />
                  </td>
                  <td className="mono">{a.action}</td>
                  <td className="mono">{a.target || '—'}</td>
                  <td className="mono muted">
                    {a.actor_kind}/{a.actor_id}
                  </td>
                  <td className="mono muted">{a.decided_by ?? '—'}</td>
                  <td className="muted" title={formatDateTime(a.decided_at ?? a.created_at)}>
                    {relativeTime(a.decided_at ?? a.created_at, now)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}

function PendingCard({ approval, now }: { approval: Approval; now: number }) {
  const decide = useDecideApproval();

  return (
    <section className="approval-card" aria-label={`Approval for ${approval.action}`}>
      <div className="approval-card-head">
        <span className="muted small">Requested {relativeTime(approval.created_at, now)}</span>
        <span className="pill pill-warn" title={formatDateTime(approval.expires_at)}>
          Expires in {timeLeft(approval.expires_at, now)}
        </span>
      </div>
      <ApprovalDetails approval={approval} />
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
            decide.mutate({ id: approval.id, approve: false });
          }}
        >
          Deny
        </button>
        <button
          className="btn btn-primary"
          type="button"
          disabled={decide.isPending}
          onClick={() => {
            decide.mutate({ id: approval.id, approve: true });
          }}
        >
          Approve
        </button>
      </div>
    </section>
  );
}
