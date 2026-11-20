import { useState } from 'react';
import { useClusterChange, useClusterMembers, type Removal, type RoleChange } from '../api/cluster.ts';
import { ApiError } from '../api/client.ts';
import {
  actionEffect,
  memberActions,
  memberState,
  refusalMessage,
  type ClusterAction,
  type ClusterMember,
} from '../cluster.ts';
import { Modal } from './Modal.tsx';
import './ClusterPage.css';

/** The members of the AP cluster, with their roles, and the role changes. */
export function ClusterPage() {
  const status = useClusterMembers();
  const [pending, setPending] = useState<{ member: ClusterMember; action: ClusterAction }>();
  const data = status.data;
  const members = [...(data?.members ?? [])].sort((a, b) => a.id.localeCompare(b.id));

  return (
    <main className="content">
      <div className="page-head">
        <div>
          <h1>Cluster</h1>
          {data ? (
            <p className="muted">
              {members.length} member{members.length === 1 ? '' : 's'} · {data.storage_members ?? 0} storage · N=
              {data.replicas ?? 0} ·{' '}
              {data.highly_available ? 'highly available' : 'not highly available (fewer than 2 storage members, or N < 2)'}
            </p>
          ) : null}
        </div>
      </div>

      {status.isError ? (
        <div className="error-box" role="alert">
          Could not load the cluster: {status.error.message}
        </div>
      ) : status.isPending ? (
        <p className="muted">Loading the cluster…</p>
      ) : (
        <div className="table-wrap">
          <table className="devices kube cluster-table">
            <thead>
              <tr>
                <th>Member</th>
                <th>Roles</th>
                <th className="cluster-wide">Allowed roles</th>
                <th>State</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {members.map((m) => (
                <MemberRow
                  key={m.id}
                  member={m}
                  self={data?.node_id ?? ''}
                  onAction={(action) => {
                    setPending({ member: m, action });
                  }}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {pending ? (
        <ClusterActionDialog
          member={pending.member}
          action={pending.action}
          onClose={() => {
            setPending(undefined);
          }}
        />
      ) : null}
    </main>
  );
}

function MemberRow({
  member: m,
  self,
  onAction,
}: {
  member: ClusterMember;
  self: string;
  onAction: (a: ClusterAction) => void;
}) {
  const state = memberState(m);
  const roles = m.roles.filter((r) => r !== 'node');
  return (
    <tr>
      <td>
        <span className="name">
          {m.id}
          {m.id === self ? <span className="muted small"> (this hub)</span> : null}
        </span>
        <span className="cluster-meta mono">{m.address}</span>
      </td>
      <td>
        <span className="chips">
          {roles.length === 0 ? <span className="muted">none</span> : null}
          {roles.map((r) => (
            <span key={r} className="chip">
              {r}
            </span>
          ))}
        </span>
      </td>
      <td className="cluster-wide muted">{m.allowed_roles.filter((r) => r !== 'node').join(', ') || 'none'}</td>
      <td>
        <span className={`pill pill-${state.tone}`}>{state.label}</span>
        {m.draining ? (
          <progress className="cluster-progress" max={100} value={m.progress ?? 0} aria-label={`${m.id} drained`} />
        ) : null}
      </td>
      <td className="row-actions">
        {memberActions(m, self).map((a) => (
          <button
            key={a.label}
            type="button"
            className={`btn btn-small${a.op === 'remove' ? ' btn-danger' : ''}`}
            aria-label={`${a.label}: ${m.id}`}
            onClick={() => {
              onAction(a);
            }}
          >
            {a.label}
          </button>
        ))}
      </td>
    </tr>
  );
}

const titles = { promote: 'Promote', demote: 'Demote', remove: 'Remove' };

/** Confirms a promotion, demotion or removal, then asks the hub. */
function ClusterActionDialog({
  member,
  action,
  onClose,
}: {
  member: ClusterMember;
  action: ClusterAction;
  onClose: () => void;
}) {
  const change = useClusterChange();
  const title =
    action.op === 'remove'
      ? `Remove ${member.id}`
      : `${titles[action.op]} ${member.id} ${action.op === 'promote' ? 'to' : 'from'} ${action.role ?? ''}`;
  const err = change.error;

  return (
    <Modal className="dialog" labelledBy="cluster-action-title" onClose={onClose}>
      <header className="dialog-head">
        <div>
          <h2 id="cluster-action-title">{title}</h2>
          <p className="muted small">
            {member.id} · {member.roles.filter((r) => r !== 'node').join(', ') || 'no role'} · {member.state}
          </p>
        </div>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate({ member: member.id, action });
        }}
      >
        <section className="plan" aria-label="What this does">
          <div className="plan-head">
            <span className="muted small">What this does</span>
            <span className="pill pill-bad">dangerous</span>
          </div>
          <p>{actionEffect(action, member.id)}</p>
        </section>

        {err ? (
          <div className="error-box" role="alert">
            {err instanceof ApiError ? refusalMessage(err.code, err.message) : err.message}
          </div>
        ) : null}
        {change.isSuccess ? (
          <div className="ok-box" role="status">
            {doneMessage(change.data)}
          </div>
        ) : null}
        {change.isPending ? (
          <p className="muted small" role="status">
            Waiting for an answer. If policy holds this action, approve it on the Approvals page.
          </p>
        ) : null}

        <div className="form-actions">
          <button className="btn btn-ghost" type="button" onClick={onClose}>
            {change.isSuccess ? 'Close' : 'Cancel'}
          </button>
          {change.isSuccess ? null : (
            <button className="btn btn-danger" type="submit" disabled={change.isPending}>
              {change.isPending ? `${titles[action.op]}…` : titles[action.op]}
            </button>
          )}
        </div>
      </form>
    </Modal>
  );
}

function doneMessage(r: RoleChange | Removal): string {
  if ('revoked' in r) {
    return `Removed. ${String(r.revoked)} hub certificate${r.revoked === 1 ? '' : 's'} revoked.`;
  }
  switch (r.state) {
    case 'syncing':
      return 'Promoted. It is copying its rows: its state shows "syncing" until it holds them all.';
    case 'draining':
      return 'Demotion under way. It hands its rows off: its state shows the progress, and it leaves storage once every row has its copies.';
  }
  return 'Done.';
}
