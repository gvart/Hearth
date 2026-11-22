import { useState } from 'react';
import { useClusterCA, useClusterChange, useClusterMembers, type Removal, type RoleChange } from '../api/cluster.ts';
import { ApiError } from '../api/client.ts';
import {
  actionEffect,
  masterCount,
  memberActions,
  memberState,
  refusalMessage,
  roleSlots,
  safeToStopLine,
  type ClusterAction,
  type ClusterMember,
  type ClusterStatus,
} from '../cluster.ts';
import { AddHubDialog } from './AddHubDialog.tsx';
import { ClusterCASection } from './ClusterCA.tsx';
import { Modal } from './Modal.tsx';
import { Meter } from './Meter.tsx';
import './ClusterPage.css';
import { Tip } from './Tip.tsx';

/** The members of the AP cluster, with their roles, and the role changes; the hub CA and new hubs. */
export function ClusterPage() {
  const status = useClusterMembers();
  const ca = useClusterCA();
  const [pending, setPending] = useState<{ member: ClusterMember; action: ClusterAction }>();
  const [adding, setAdding] = useState(false);
  const data = status.data;
  const members = [...(data?.members ?? [])].sort((a, b) => a.id.localeCompare(b.id));
  // No hub joins during a rotation: every member takes part from its start.
  const rotating = ca.data?.rotation?.active === true;

  return (
    <main className="content">
      <div className="page-head">
        <div>
          <h1>
            Cluster <Tip id="cluster" />
          </h1>
          {data ? (
            <p className="muted">
              {members.length} member{members.length === 1 ? '' : 's'} · {data.storage_members ?? 0} storage · N=
              {data.replicas ?? 0} ·{' '}
              {data.highly_available ? 'highly available' : 'not highly available (fewer than 2 storage members, or N < 2)'}
            </p>
          ) : null}
        </div>
        <button
          className="btn btn-primary"
          type="button"
          disabled={rotating}
          title={rotating ? 'No hub can join during a hub CA rotation: finish or abort it first.' : undefined}
          onClick={() => {
            setAdding(true);
          }}
        >
          Add hub
        </button>
      </div>

      {status.isError ? (
        <div className="error-box" role="alert">
          Could not load the cluster: {status.error.message}
        </div>
      ) : status.isPending ? (
        <p className="muted">Loading the cluster…</p>
      ) : (
        <>
          <dl className="cluster-facts">
            <div className="cluster-fact">
              <dt>Masters</dt>
              <dd className="cluster-fact-n">{masterCount(members)}</dd>
              <dd className="muted small">Serve the UI, the API and agents. No leader: open any of them.</dd>
            </div>
            <div className="cluster-fact">
              <dt>Storage members</dt>
              <dd className="cluster-fact-n">{data?.storage_members ?? 0}</dd>
              <dd className="muted small">Each keeps a share of the store.</dd>
            </div>
            <div className="cluster-fact">
              <dt>Copies of each row</dt>
              <dd className="cluster-fact-n">{data?.replicas ?? 0}</dd>
              <dd className="muted small">How many storage members hold every row (N).</dd>
            </div>
            <div className="cluster-fact">
              <dt>Survives losing a hub</dt>
              <dd>
                <span className={`pill ${data?.highly_available ? 'pill-ok' : 'pill-warn'}`}>
                  {data?.highly_available ? 'yes' : 'not yet'}
                </span>
              </dd>
              <dd className="muted small">
                {data?.highly_available
                  ? 'Any one hub can fail and nothing is lost.'
                  : 'It needs 2 storage members and 2 copies of each row.'}
              </dd>
            </div>
          </dl>
          {data ? <SafeToStopLine status={data} /> : null}
          <div className="member-grid">
            {members.map((m) => (
              <MemberCard
                key={m.id}
                member={m}
                self={data?.node_id ?? ''}
                onAction={(action) => {
                  setPending({ member: m, action });
                }}
              />
            ))}
          </div>
        </>
      )}

      <ClusterCASection />

      {adding ? (
        <AddHubDialog
          onClose={() => {
            setAdding(false);
          }}
        />
      ) : null}

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

/** Whether the hub showing the page can stop now: green, or what is missing. */
function SafeToStopLine({ status }: { status: ClusterStatus }) {
  const line = safeToStopLine(status);
  if (!line) {
    return null;
  }
  return (
    <section className={`safe-stop ${line.ok ? 'safe-stop-ok' : 'safe-stop-warn'}`} aria-label="Safe to stop this hub">
      <p className="safe-stop-title">
        <span className={`pill ${line.ok ? 'pill-ok' : 'pill-warn'}`}>{line.ok ? 'safe' : 'not yet'}</span>
        <strong>{line.title}</strong> <span className="muted">({status.node_id})</span>
      </p>
      {line.ok ? (
        <p className="muted small">{line.reasons[0]}</p>
      ) : (
        <ul className="safe-stop-reasons">
          {line.reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** A member as a card: who it is, its state, and a slot for each of the two roles. */
function MemberCard({
  member: m,
  self,
  onAction,
}: {
  member: ClusterMember;
  self: string;
  onAction: (a: ClusterAction) => void;
}) {
  const state = memberState(m);
  const remove = memberActions(m, self).find((a) => a.op === 'remove');
  return (
    <section className="panel-card member-card" aria-label={m.id}>
      <div className="panel-card-head">
        <div className="member-id">
          <h2 className="mono">{m.id}</h2>
          <span className="cluster-meta mono">{m.address}</span>
        </div>
        <span className="member-state">
          {m.id === self ? <span className="badge badge-quiet">this hub</span> : null}
          <span className={`pill pill-${state.tone}`}>{state.label}</span>
        </span>
      </div>
      {m.draining ? <Meter label="Drain" percent={m.progress ?? 0} plain /> : null}
      <div className="role-slots">
        {roleSlots(m).map((slot) => {
          const action = slot.action;
          return (
            <div key={slot.role} className={`role-slot role-${slot.state}`}>
              <span className="role-name">{slot.role}</span>
              <span className="role-text small">{slot.text}</span>
              {action ? (
                <button
                  type="button"
                  className="btn btn-small"
                  aria-label={`${action.label}: ${m.id}`}
                  onClick={() => {
                    onAction(action);
                  }}
                >
                  {action.op === 'promote' ? 'Promote' : 'Demote'}
                </button>
              ) : null}
            </div>
          );
        })}
      </div>
      {remove ? (
        <div className="member-foot">
          <button
            type="button"
            className="btn btn-small btn-ghost"
            aria-label={`Remove: ${m.id}`}
            onClick={() => {
              onAction(remove);
            }}
          >
            Remove from the cluster
          </button>
        </div>
      ) : null}
    </section>
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
