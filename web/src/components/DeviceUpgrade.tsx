import { useEffect, useState } from 'react';
import { ApiError, type AgentVersion, type Device } from '../api/client.ts';
import { useDeviceDetail, useUpgradeDevice } from '../api/upgrade.ts';
import { Command } from './AddDeviceDialog.tsx';
import { Modal } from './Modal.tsx';
import { Tip } from './Tip.tsx';

/** How long the dialog waits for the upgraded agent to come back before it says to look at the device. */
const backWithin = 90_000;

/**
 * The agent's version next to the hub's, and the way to bring it up to the
 * hub's (#347): "Upgrade agent" for an agent that upgrades itself, the
 * installer's command for one too old to, and why not for one that will not
 * (a Kubernetes pod). Nothing while the agent is up to date.
 */
export function DeviceUpgrade({ device }: { device: Device }) {
  const v = device.agent_version;
  const tooOld = v !== undefined && v.upgrade_available && !v.remote_upgrade && !v.no_remote_upgrade;
  const detail = useDeviceDetail(device.id, tooOld);
  const [open, setOpen] = useState(false);
  if (!v || (!v.upgrade_available && !open)) {
    return null;
  }
  const command = detail.data?.agent_version?.install_command;
  const online = device.status === 'online';

  return (
    <section className="panel-card" aria-label="Agent version">
      <div className="panel-card-head">
        <h2 className="card-label">
          Agent version <Tip id="upgrade" />
        </h2>
        {v.upgrade_available ? <span className="pill pill-warn">out of date</span> : null}
      </div>
      <p className="small">
        Runs <span className="mono">{v.agent}</span>; the hub runs <span className="mono">{v.hub}</span>.
      </p>
      {v.remote_upgrade ? (
        <>
          {online ? null : <p className="muted small">The agent is offline: it can upgrade once it is back.</p>}
          <div className="form-actions">
            <button
              type="button"
              className="btn"
              disabled={!online}
              onClick={() => {
                setOpen(true);
              }}
            >
              Upgrade agent
            </button>
          </div>
        </>
      ) : v.no_remote_upgrade ? (
        <p className="muted small">{v.no_remote_upgrade}.</p>
      ) : (
        <>
          <p className="muted small">
            This agent is too old to upgrade itself. Upgrade it once by running this on the device; after that, you
            upgrade it from here.
          </p>
          {command ? <Command label="On the device" value={command} /> : null}
        </>
      )}
      {open ? (
        <UpgradeDialog
          device={device}
          version={v}
          onClose={() => {
            setOpen(false);
          }}
        />
      ) : null}
    </section>
  );
}

/** Confirms the upgrade, then follows it: the download and check, the restart, the agent back on the new version. */
function UpgradeDialog({ device, version, onClose }: { device: Device; version: AgentVersion; onClose: () => void }) {
  const upgrade = useUpgradeDevice(device.id);
  const name = device.name || device.hostname;
  const target = upgrade.data?.version;
  const back = target !== undefined && device.status === 'online' && device.agent_version?.agent === target;
  const [late, setLate] = useState(false);
  useEffect(() => {
    if (target === undefined || back) {
      return;
    }
    const t = setTimeout(() => {
      setLate(true);
    }, backWithin);
    return () => {
      clearTimeout(t);
    };
  }, [target, back]);
  const err = upgrade.error;

  return (
    <Modal className="dialog" labelledBy="upgrade-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="upgrade-title">Upgrade the agent of {name}</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          upgrade.mutate();
        }}
      >
        <section className="plan" aria-label="What this does">
          <div className="plan-head">
            <span className="muted small">What this does</span>
            <span className="pill pill-bad">dangerous</span>
          </div>
          <p>
            The agent downloads Hearth <span className="mono">{version.hub}</span> from GitHub, checks it against the
            release&apos;s checksums, replaces its binary (keeping the old one as <code>hearth.prev</code>) and restarts.
          </p>
          <p>The device is offline for a few seconds while the agent restarts.</p>
        </section>
        {err ? (
          <div className="error-box" role="alert">
            {upgradeRefusal(err)}
          </div>
        ) : null}
        {upgrade.isPending ? (
          <p className="muted small" role="status">
            Downloading and checking {version.hub} on the device… If policy holds this action, approve it on the
            Approvals page.
          </p>
        ) : null}
        {target !== undefined && !back ? (
          <p className="muted small" role="status">
            {late
              ? 'The agent has not come back yet. Check its service on the device: systemctl status hearth-agent, or launchctl print system/dev.hearth.agent on a Mac.'
              : `The new binary is in place. Restarting with ${target}…`}
          </p>
        ) : null}
        {back ? (
          <div className="ok-box" role="status">
            Done: the agent is back and runs {target}.
          </div>
        ) : null}
        <div className="form-actions">
          <button className="btn btn-ghost" type="button" onClick={onClose}>
            {target !== undefined ? 'Close' : 'Cancel'}
          </button>
          {target !== undefined ? null : (
            <button className="btn btn-danger" type="submit" disabled={upgrade.isPending}>
              {upgrade.isPending ? 'Upgrading…' : `Upgrade to ${version.hub}`}
            </button>
          )}
        </div>
      </form>
    </Modal>
  );
}

/** What a refused or failed upgrade tells the admin. */
function upgradeRefusal(err: Error): string {
  if (!(err instanceof ApiError)) {
    return err.message;
  }
  switch (err.code) {
    case 'release_unreachable':
      return `${err.message}. Upgrading from a local mirror is not supported yet.`;
    case 'forbidden':
      return 'Denied by policy.';
    case 'agent_not_connected':
      return 'The agent is not connected: it can upgrade once it is back.';
  }
  return err.message;
}
