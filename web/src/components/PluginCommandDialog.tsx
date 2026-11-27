import { useState } from 'react';
import { usePluginCommand, type Plugin, type PluginCommandSpec, type PluginDevice, type PolicyDecision } from '../api/plugins.ts';
import { parseArgs } from '../plugincommands.ts';
import { Modal } from './Modal.tsx';

const pillOf = { read: 'pill-ok', safe: 'pill-ok', dangerous: 'pill-bad' } as const;

/**
 * Confirms a command a plugin declares, then runs it through policy with the
 * class its manifest declares. Says before the run whether policy would hold
 * or refuse it, and waits, while it is held, for an operator's approval.
 */
export function PluginCommandDialog({
  plugin,
  device,
  command,
  decision,
  onClose,
}: {
  plugin: Plugin;
  device?: PluginDevice;
  command: PluginCommandSpec;
  decision: PolicyDecision;
  onClose: () => void;
}) {
  const run = usePluginCommand(plugin.name);
  const [argsText, setArgsText] = useState('');
  const parsed = parseArgs(argsText);
  const dangerous = command.class === 'dangerous';
  const denied = decision === 'deny';
  const stopped = plugin.state !== 'running';

  return (
    <Modal className="dialog" labelledBy="plugin-cmd-title" onClose={onClose}>
      <header className="dialog-head">
        <div>
          <h2 id="plugin-cmd-title">
            <span className="mono">{command.name}</span>
            {device ? ` · ${device.name || device.id}` : ''}
          </h2>
          <p className="muted small">
            Plugin {plugin.name} {plugin.version}
            {device ? ` · device ${device.id}` : ''}
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
          if (parsed.error) {
            return;
          }
          run.mutate({ command: command.name, device: device?.id, args: parsed.args });
        }}
      >
        <section className="plan" aria-label="What this does">
          <div className="plan-head">
            <span className="muted small">What this does</span>
            <span className={`pill ${pillOf[command.class]}`} title="The class the plugin's manifest declares">
              {command.class}
            </span>
          </div>
          <p>{command.description || `Sends ${command.name} to the plugin ${plugin.name}.`}</p>
        </section>

        {denied ? (
          <div className="error-box" role="alert">
            Policy denies {command.class} plugin commands from the web UI. Nothing is sent to the plugin.
          </div>
        ) : decision === 'confirm' ? (
          <div className="warn-box" role="note">
            Policy holds {command.class} plugin commands for approval: this one runs once an operator approves it on the
            Approvals page.
          </div>
        ) : null}
        {stopped && !denied ? (
          <div className="warn-box" role="note">
            The plugin is {plugin.state}: the command fails unless it is running again by then.
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
            disabled={denied || run.isPending || run.isSuccess}
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
              disabled={denied || run.isPending || parsed.error !== undefined}
            >
              {run.isPending ? 'Running…' : decision === 'confirm' ? 'Ask for approval' : 'Run'}
            </button>
          )}
        </div>
      </form>
    </Modal>
  );
}
