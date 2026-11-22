import { useState } from 'react';
import { ApiError, type Device } from '../api/client.ts';
import { isNotAPCluster, useClusterChange, useDeviceHub, useMakeDeviceHub, type Removal, type RoleChange } from '../api/cluster.ts';
import {
  actionEffect,
  memberState,
  refusalMessage,
  roleSlots,
  type ClusterAction,
  type ClusterMember,
} from '../cluster.ts';
import { capsLine, hubMember, hubRoleLine, makeHubBlocked, makeHubEffect, type DeviceHub as Hub } from '../devicehub.ts';
import { Command } from './AddDeviceDialog.tsx';
import { Modal } from './Modal.tsx';
import { Tip } from './Tip.tsx';
import './ClusterPage.css';

/**
 * Whether the device is a hub of the cluster too (#332): its roles with
 * promote and demote, and "Make agent-only"; or, for an agent only, "Make
 * this device a hub". Nothing on a hub outside an AP cluster.
 */
/**
 * The dialog open on the card, with what it was opened for: the card's data
 * changes under it (a removed hub is no member any more), the dialog's not.
 */
type Dialog =
  | { kind: 'make'; hub: Hub }
  | { kind: 'agent-only'; hub: Hub; member: ClusterMember }
  | { kind: 'role'; member: ClusterMember; action: ClusterAction };

export function DeviceHubSection({ device }: { device: Device }) {
  const hub = useDeviceHub(device.id);
  const [dialog, setDialog] = useState<Dialog>();
  const close = () => {
    setDialog(undefined);
  };
  if (isNotAPCluster(hub.error)) {
    return null;
  }
  const h = hub.data;
  const member = h ? hubMember(h) : undefined;

  return (
    <section className="panel-card card-wide" aria-label="Hub">
      <div className="panel-card-head">
        <h2 className="card-label">
          Hub <Tip id="devicehub" />
        </h2>
        {member ? <MemberPill member={member} /> : h ? <span className="pill pill-muted">agent only</span> : null}
      </div>
      {hub.isError ? (
        <div className="error-box" role="alert">
          Could not load the device&apos;s hub: {hub.error.message}
        </div>
      ) : !h ? (
        <p className="muted small">Loading…</p>
      ) : member ? (
        <>
          <p className="small">
            {hubRoleLine(h)} Member <span className="mono">{member.id}</span>.
          </p>
          <div className="role-slots">
            {roleSlots(member).map((slot) => (
              <div key={slot.role} className={`role-slot role-${slot.state}`}>
                <span className="role-name">{slot.role}</span>
                <span className="role-text small">{slot.text}</span>
                {slot.action ? (
                  <button
                    type="button"
                    className="btn btn-small"
                    aria-label={`${slot.action.label}: ${member.id}`}
                    onClick={() => {
                      if (slot.action) {
                        setDialog({ kind: 'role', member, action: slot.action });
                      }
                    }}
                  >
                    {slot.action.op === 'promote' ? 'Promote' : 'Demote'}
                  </button>
                ) : null}
              </div>
            ))}
          </div>
          <div className="member-foot">
            <span className="muted small">{capsLine(h)}</span>
            <button
              type="button"
              className="btn btn-small btn-ghost"
              onClick={() => {
                setDialog({ kind: 'agent-only', hub: h, member });
              }}
            >
              Make agent-only
            </button>
          </div>
        </>
      ) : (
        <AgentOnly
          hub={h}
          device={device}
          onMake={() => {
            setDialog({ kind: 'make', hub: h });
          }}
        />
      )}

      {dialog?.kind === 'make' ? <MakeHubDialog device={device} hub={dialog.hub} onClose={close} /> : null}
      {dialog?.kind === 'agent-only' ? (
        <AgentOnlyDialog device={device} hub={dialog.hub} member={dialog.member} onClose={close} />
      ) : null}
      {dialog?.kind === 'role' ? <RoleDialog member={dialog.member} action={dialog.action} onClose={close} /> : null}
    </section>
  );
}

function MemberPill({ member }: { member: ClusterMember }) {
  const s = member.state === 'unknown' ? { label: 'joining', tone: 'warn' } : memberState(member);
  return <span className={`pill pill-${s.tone}`}>{s.label}</span>;
}

/** An agent only: why it is not a hub, and the way to make it one. */
function AgentOnly({ hub, device, onMake }: { hub: Hub; device: Device; onMake: () => void }) {
  const blocked = makeHubBlocked(hub, device.os, device.arch);
  return (
    <>
      <p className="small">{hubRoleLine(hub)}</p>
      <p className="muted small">
        A hub keeps a copy of the cluster&apos;s data and, as a master, serves this UI: the cluster carries on when
        another hub stops. {capsLine(hub)}.
      </p>
      {blocked ? <p className="muted small">{blocked}</p> : null}
      <div className="form-actions">
        <button type="button" className="btn" disabled={blocked !== undefined} onClick={onMake}>
          Make this device a hub
        </button>
      </div>
    </>
  );
}

/** Mints the device's join token, with the password again, and shows the command that uses it once. */
function MakeHubDialog({ device, hub, onClose }: { device: Device; hub: Hub; onClose: () => void }) {
  const make = useMakeDeviceHub(device.id);
  const res = make.data;
  const err = make.error;
  return (
    <Modal className="dialog" labelledBy="make-hub-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="make-hub-title">Make {device.name || device.hostname} a hub</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      {res ? (
        <div className="form">
          <Command label="On the device" value={res.command} />
          <p className="muted small">
            Single use · grants {res.roles.join(' and ')} · expires at{' '}
            {new Date(res.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </p>
          <div className="notice">
            Shown once. The command re-runs the installer: it keeps the agent and its identity, and installs the hub
            service next to it. The device shows here as a hub once it has joined.
          </div>
          <div className="form-actions">
            <button className="btn btn-primary" type="button" onClick={onClose}>
              Done
            </button>
          </div>
        </div>
      ) : (
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            make.mutate();
          }}
        >
          <section className="plan" aria-label="What this does">
            <div className="plan-head">
              <span className="muted small">What this does</span>
              <span className="pill pill-bad">dangerous</span>
            </div>
            <p>{makeHubEffect(hub)}</p>
            <p>
              It creates a single-use join token for this device and the command to run on it. The device checks it has
              1.5 GiB of memory and 2 GiB free before it joins.
            </p>
          </section>
          {err ? (
            <div className="error-box" role="alert">
              {err instanceof ApiError ? refusalMessage(err.code, err.message) : err.message}
            </div>
          ) : null}
          {make.isPending ? (
            <p className="muted small" role="status">
              Waiting for an answer. If policy holds this action, approve it on the Approvals page.
            </p>
          ) : null}
          <div className="form-actions">
            <button className="btn btn-ghost" type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="btn btn-danger" type="submit" disabled={make.isPending}>
              {make.isPending ? 'Creating…' : 'Create the command'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}

/** Removes the device's hub from the cluster and shows the re-run that takes its service away. */
function AgentOnlyDialog({
  device,
  hub,
  member,
  onClose,
}: {
  device: Device;
  hub: Hub;
  member: ClusterMember;
  onClose: () => void;
}) {
  const change = useClusterChange();
  const command = hub.agent_only_command;
  const err = change.error;
  return (
    <Modal className="dialog" labelledBy="agent-only-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="agent-only-title">Make {device.name || device.hostname} agent-only</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate({ member: member.id, action: { op: 'remove', label: 'Remove' } });
        }}
      >
        <section className="plan" aria-label="What this does">
          <div className="plan-head">
            <span className="muted small">What this does</span>
            <span className="pill pill-bad">dangerous</span>
          </div>
          <p>{actionEffect({ op: 'remove', label: 'Remove' }, member.id)}</p>
          <p>The cluster refuses to remove its last master or its last storage member, and the hub you are using.</p>
        </section>
        <Command label="Then, on the device: stop and remove the hub service (the agent stays)" value={command} />
        {err ? (
          <div className="error-box" role="alert">
            {err instanceof ApiError ? removalRefusal(err) : err.message}
          </div>
        ) : null}
        {change.isSuccess ? (
          <div className="ok-box" role="status">
            {doneMessage(change.data)} Run the command above on the device.
          </div>
        ) : null}
        <div className="form-actions">
          <button className="btn btn-ghost" type="button" onClick={onClose}>
            {change.isSuccess ? 'Close' : 'Cancel'}
          </button>
          {change.isSuccess ? null : (
            <button className="btn btn-danger" type="submit" disabled={change.isPending}>
              {change.isPending ? 'Removing…' : 'Remove from the cluster'}
            </button>
          )}
        </div>
      </form>
    </Modal>
  );
}

function removalRefusal(err: ApiError): string {
  if (err.code === 'remove_self') {
    return 'This is the hub you are using: open the UI of another master to remove it.';
  }
  return refusalMessage(err.code, err.message);
}

/** Confirms a promotion or demotion of the device's hub, as the Cluster page does. */
function RoleDialog({ member, action, onClose }: { member: ClusterMember; action: ClusterAction; onClose: () => void }) {
  const change = useClusterChange();
  const err = change.error;
  const verb = action.op === 'promote' ? 'Promote' : 'Demote';
  return (
    <Modal className="dialog" labelledBy="role-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="role-title">
          {verb} {member.id} {action.op === 'promote' ? 'to' : 'from'} {action.role}
        </h2>
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
        <div className="form-actions">
          <button className="btn btn-ghost" type="button" onClick={onClose}>
            {change.isSuccess ? 'Close' : 'Cancel'}
          </button>
          {change.isSuccess ? null : (
            <button className="btn btn-danger" type="submit" disabled={change.isPending}>
              {change.isPending ? `${verb}…` : verb}
            </button>
          )}
        </div>
      </form>
    </Modal>
  );
}

function doneMessage(r: RoleChange | Removal): string {
  if ('revoked' in r) {
    return `Removed from the cluster: ${String(r.revoked)} hub certificate${r.revoked === 1 ? '' : 's'} revoked.`;
  }
  switch (r.state) {
    case 'syncing':
      return 'Promoted. It copies its rows and shows "syncing" until it holds them all.';
    case 'draining':
      return 'Demotion under way: it hands its rows off, then leaves storage.';
  }
  return 'Done.';
}
