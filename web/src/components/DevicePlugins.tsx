import { useState } from 'react';
import type { Device } from '../api/client.ts';
import { useDevicePluginCommand, useDevicePlugins, type DevicePluginState } from '../api/deviceplugins.ts';
import type { PluginCommandSpec, PolicyDecision } from '../api/plugins.ts';
import { classPill, parseArgs } from '../plugincommands.ts';
import { Modal } from './Modal.tsx';
import './PluginDevices.css';

interface Picked {
  plugin: DevicePluginState;
  command: PluginCommandSpec;
  decision: PolicyDecision;
}

/**
 * The device plugins the hub granted this device (under Capabilities): whether
 * each is installed, and a button per command it may run. Renders nothing
 * while the device has none.
 */
export function DevicePlugins({ device }: { device: Device }) {
  const q = useDevicePlugins(device.id);
  const [picked, setPicked] = useState<Picked>();
  const data = q.data;
  if (q.isError) {
    return (
      <section className="panel-card card-wide" aria-label="Plugins">
        <h2 className="card-label">Plugins</h2>
        <div className="error-box" role="alert">
          Could not load the device&apos;s plugins: {q.error.message}
        </div>
      </section>
    );
  }
  if (!data || (data.supported && data.plugins.length === 0)) {
    return null;
  }
  return (
    <section className="panel-card card-wide" aria-label="Plugins">
      <h2 className="card-label">Plugins</h2>
      {!data.supported ? (
        <p className="muted small">Plugins need an agent upgrade.</p>
      ) : (
        <>
          {data.connected ? null : <p className="muted small">The device is not connected: commands wait until it is.</p>}
          <ul className="caps-list">
            {data.plugins.map((p) => (
              <li key={p.name} className="caps-row">
                <div className="caps-what">
                  <span className="caps-name">
                    {p.name}
                    {p.version ? <span className="muted small mono">{p.version}</span> : null}
                    <span className={`pill ${classPill[p.max_class]}`} title="The highest class the hub may run here">
                      up to {p.max_class}
                    </span>
                  </span>
                  {p.error ? (
                    <span className="small" role="alert" style={{ color: 'var(--danger)' }}>
                      {p.error}
                    </span>
                  ) : !p.installed ? (
                    <span className="muted small">Not installed yet{data.connected ? ': the agent fetches it.' : '.'}</span>
                  ) : null}
                </div>
                <div className="plugin-commands">
                  {p.commands.map((c) => {
                    const decision = data.decisions[c.class];
                    return (
                      <button
                        key={c.name}
                        type="button"
                        className="btn btn-ghost btn-small"
                        disabled={!p.installed || !data.connected || !c.allowed || decision === 'deny'}
                        title={
                          !c.allowed
                            ? `Beyond what the hub may run here (up to ${p.max_class})`
                            : decision === 'deny'
                              ? `Policy denies ${c.class} commands`
                              : decision === 'confirm'
                                ? `${c.description ?? c.name} (held for approval)`
                                : c.description
                        }
                        onClick={() => {
                          setPicked({ plugin: p, command: c, decision });
                        }}
                      >
                        {c.name}
                        <span className={`pill ${classPill[c.class]}`}>{c.class}</span>
                      </button>
                    );
                  })}
                </div>
              </li>
            ))}
          </ul>
        </>
      )}
      {picked ? (
        <CommandDialog
          deviceId={device.id}
          picked={picked}
          onClose={() => {
            setPicked(undefined);
          }}
        />
      ) : null}
    </section>
  );
}

/** Confirms a command, then runs it on the device through policy and shows what it printed. */
function CommandDialog({ deviceId, picked, onClose }: { deviceId: string; picked: Picked; onClose: () => void }) {
  const { plugin, command, decision } = picked;
  const run = useDevicePluginCommand(deviceId, plugin.name);
  const [argsText, setArgsText] = useState('');
  const parsed = parseArgs(argsText);
  const dangerous = command.class === 'dangerous';
  return (
    <Modal className="dialog" labelledBy="device-plugin-cmd-title" onClose={onClose}>
      <header className="dialog-head">
        <div>
          <h2 id="device-plugin-cmd-title">
            <span className="mono">{command.name}</span>
          </h2>
          <p className="muted small">
            Plugin {plugin.name}
            {plugin.version ? ` ${plugin.version}` : ''}, on this device
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
          if (!parsed.error) {
            run.mutate({ command: command.name, args: parsed.args });
          }
        }}
      >
        <section className="plan" aria-label="What this does">
          <div className="plan-head">
            <span className="muted small">What this does</span>
            <span className={`pill ${classPill[command.class]}`}>{command.class}</span>
          </div>
          <p>{command.description || `Runs ${command.name} of the plugin ${plugin.name} on the device.`}</p>
        </section>
        {dangerous ? (
          <div className="warn-box" role="note">
            This command is dangerous: it can change the device.
          </div>
        ) : null}
        {decision === 'confirm' ? (
          <div className="warn-box" role="note">
            Policy holds {command.class} plugin commands for approval: this one runs once an operator approves it on the
            Approvals page.
          </div>
        ) : null}
        <label className="field">
          <span>
            Arguments <span className="muted small">(optional JSON object)</span>
          </span>
          <textarea
            rows={2}
            spellCheck={false}
            className="mono"
            value={argsText}
            placeholder="{}"
            aria-invalid={parsed.error ? 'true' : undefined}
            disabled={run.isPending || run.isSuccess}
            onChange={(e) => {
              setArgsText(e.target.value);
            }}
          />
        </label>
        {parsed.error ? <p className="field-error small">{parsed.error}</p> : null}
        {run.isError ? (
          <div className="error-box" role="alert">
            {run.error.message}
          </div>
        ) : null}
        {run.isSuccess ? (
          <div className="ok-box" role="status">
            {run.data.output ? <pre className="plugin-output">{run.data.output}</pre> : 'Done. The plugin printed nothing.'}
          </div>
        ) : null}
        {run.isPending ? (
          <p className="muted small" role="status">
            {decision === 'confirm'
              ? 'Held for approval. Approve it on the Approvals page; this dialog waits for the answer.'
              : 'Waiting for the plugin to answer.'}
          </p>
        ) : null}
        <div className="form-actions">
          <button className="btn btn-ghost" type="button" onClick={onClose}>
            {run.isSuccess ? 'Close' : 'Cancel'}
          </button>
          {run.isSuccess ? null : (
            <button
              className={`btn ${dangerous ? 'btn-danger' : 'btn-primary'}`}
              type="submit"
              disabled={run.isPending || parsed.error !== undefined}
            >
              {run.isPending ? 'Running…' : decision === 'confirm' ? 'Ask for approval' : dangerous ? 'Run anyway' : 'Run'}
            </button>
          )}
        </div>
      </form>
    </Modal>
  );
}
