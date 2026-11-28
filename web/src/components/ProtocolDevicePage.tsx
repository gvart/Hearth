import { useState, type ReactNode } from 'react';
import type { Device } from '../api/client.ts';
import { ApiError } from '../api/client.ts';
import { useProtocolCommand, useRemoveProtocolDevice, type ProtocolCommandResult } from '../api/deviceprotocol.ts';
import {
  parseParams,
  protocolEntityKindLabel,
  protocolValueText,
  type ProtocolCommandSpec,
  type ProtocolFacts,
} from '../deviceprotocol.ts';
import { displayName, formatDateTime, relativeTime, statusLabel } from '../format.ts';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import { StatusDot } from './StatusDot.tsx';
import './ProtocolDevicePage.css';

/**
 * The page of a device that joined over MQTT with the Device Protocol
 * (docs/spec/device-protocol-v1.md): it has no agent, so none of an agent's
 * panels. It shows what the device announced, its latest state and readings,
 * which follow the device's events, a form per command it takes, and its
 * removal.
 */
export function ProtocolDevicePage({ device, facts, now }: { device: Device; facts: ProtocolFacts; now: number }) {
  const labels = Object.entries(device.labels);
  const telemetry = Object.entries(facts.telemetry).sort(([a], [b]) => a.localeCompare(b));
  const about = [facts.manufacturer, facts.model].filter(Boolean).join(' ');
  return (
    <main className="content device-page">
      <a className="back-link" href="#/">
        ‹ Devices
      </a>
      <div className="page-head">
        <div>
          <h1>{displayName(device)}</h1>
          <p className="muted status-line">
            <StatusDot status={device.status} /> {statusLabel(device.status)}
            <span> · Device Protocol</span>
            {about ? <span> · {about}</span> : null}
          </p>
        </div>
      </div>

      <div className="device-grid">
        <Section title={`Entities (${String(facts.entities.length)})`} wide>
          {facts.entities.length ? (
            <table className="mini">
              <thead>
                <tr>
                  <th>Entity</th>
                  <th>Kind</th>
                  <th className="num">Value</th>
                </tr>
              </thead>
              <tbody>
                {facts.entities.map((e) => (
                  <tr key={e.id}>
                    <td>
                      {e.name || e.id}
                      {e.name ? <span className="disk-sub mono">{e.id}</span> : null}
                    </td>
                    <td className="muted">{protocolEntityKindLabel[e.kind]}</td>
                    <td className="num mono">{protocolValueText(e, facts.state[e.id])}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="muted small">The device announced no entities.</p>
          )}
          <p className="muted small">
            Updated {device.status === 'online' ? relativeTime(facts.updated_at, now) : formatDateTime(facts.updated_at)}.
            Hearth keeps the latest value of each.
          </p>
        </Section>

        <Section title={`Commands (${String(facts.commands.length)})`} wide>
          {facts.commands.length ? (
            <>
              <p className="muted small">
                Each command is a{' '}
                <span className={`pill pill-${facts.command_class === 'dangerous' ? 'warn' : 'ok'}`}>
                  {facts.command_class || 'dangerous'}
                </span>{' '}
                action: Hearth cannot know what the device does with it, so it asks for the admin password again, and
                audits it.
              </p>
              {device.status !== 'online' ? (
                <p className="muted small">The device is offline: it gets no commands until it connects again.</p>
              ) : null}
              {facts.commands.map((c) => (
                <CommandForm key={c.name} device={device} spec={c} />
              ))}
            </>
          ) : (
            <p className="muted small">The device announced no commands.</p>
          )}
        </Section>

        <Section title="Device">
          <Row k="ID" v={<span className="mono">{device.id}</span>} />
          <Row k="Protocol id" v={<span className="mono">{facts.id}</span>} />
          <Row k="Model" v={facts.model} />
          <Row k="Manufacturer" v={facts.manufacturer} />
          <Row k="Software" v={facts.sw_version} />
          <Row k="First seen" v={formatDateTime(device.first_seen)} />
          <Row
            k="Last seen"
            v={device.status === 'online' ? 'now' : device.status === 'unknown' ? undefined : relativeTime(device.last_seen, now)}
          />
          <Row
            k="Labels"
            v={
              labels.length ? (
                <span className="chips">
                  {labels.map(([k, v]) => (
                    <span className="chip" key={k}>
                      {k}={v}
                    </span>
                  ))}
                </span>
              ) : undefined
            }
          />
        </Section>

        <Section title={`Telemetry (${String(telemetry.length)})`}>
          {telemetry.length ? (
            telemetry.map(([k, v]) => <Row key={k} k={k} v={<span className="mono">{v ?? '—'}</span>} />)
          ) : (
            <p className="muted small">Not reported yet.</p>
          )}
        </Section>

        <Section title="Access">
          <RemoveProtocolDevice device={device} facts={facts} />
        </Section>
      </div>
    </main>
  );
}

/** One command the device announced: its params, if it takes any, and its last result. */
function CommandForm({ device, spec }: { device: Device; spec: ProtocolCommandSpec }) {
  const [params, setParams] = useState('');
  const [invalid, setInvalid] = useState('');
  const send = useProtocolCommand(device.id);
  const fieldId = `params-${spec.name}`;
  const failed = send.isError ? failedResult(send.error) : undefined;
  return (
    <form
      className="protocol-command"
      onSubmit={(e) => {
        e.preventDefault();
        const p = parseParams(params);
        if (!p.ok) {
          setInvalid(p.error);
          return;
        }
        setInvalid('');
        send.mutate({ command: spec.name, params: p.params });
      }}
    >
      <div className="protocol-command-name">
        <span className="mono">{spec.name}</span>
        {spec.description ? <span className="muted small">{spec.description}</span> : null}
      </div>
      <input
        id={fieldId}
        className="mono"
        type="text"
        aria-label={`Params of ${spec.name} (optional JSON object)`}
        placeholder="params, optional JSON object"
        value={params}
        onChange={(e) => {
          setParams(e.target.value);
        }}
        spellCheck={false}
        autoComplete="off"
      />
      <button className="btn btn-small" type="submit" disabled={send.isPending || device.status !== 'online'}>
        {send.isPending ? 'Sending…' : 'Send'}
      </button>
      {invalid ? (
        <p className="error-box small protocol-command-result" role="alert">
          {invalid}
        </p>
      ) : null}
      {send.isSuccess ? (
        <p className="ok-box small protocol-command-result" role="status">
          OK{send.data.message ? `: ${send.data.message}` : ''}
        </p>
      ) : null}
      {send.isError ? (
        <p className="error-box small protocol-command-result" role="alert">
          {failed ? `The device answered that it failed${failed.message ? `: ${failed.message}` : ''}.` : send.error.message}
        </p>
      ) : null}
    </form>
  );
}

/** The device's own answer, when it said the command failed (a 502 that carries it). */
function failedResult(err: Error): ProtocolCommandResult | undefined {
  if (err instanceof ApiError && err.code === 'command_failed') {
    return err.body as ProtocolCommandResult;
  }
  return undefined;
}

/** Removes the device and its MQTT user, as `hearth device remove` does. */
function RemoveProtocolDevice({ device, facts }: { device: Device; facts: ProtocolFacts }) {
  const [open, setOpen] = useState(false);
  const remove = useRemoveProtocolDevice();
  return (
    <>
      <p className="muted small">
        Removing takes the device&apos;s MQTT user out of this hub&apos;s clients file, which disconnects it and refuses its
        next login, then the device itself.
      </p>
      <div>
        <button
          className="btn btn-danger btn-small"
          type="button"
          onClick={() => {
            remove.reset();
            setOpen(true);
          }}
        >
          Remove device
        </button>
      </div>
      {open ? (
        <ConfirmDialog
          title={`Remove ${displayName(device)}`}
          actionClass="dangerous"
          confirmLabel="Remove"
          pendingLabel="Removing…"
          pending={remove.isPending}
          error={remove.isError ? remove.error.message : undefined}
          done={
            remove.isSuccess ? (
              remove.data.mqtt_user_removed ? (
                <>
                  Removed. Its MQTT user <span className="mono">{facts.id}</span> is gone from this hub&apos;s clients file:
                  the device cannot log in again until you give it a user anew.
                </>
              ) : (
                <>
                  Removed, but this hub&apos;s clients file had no MQTT user <span className="mono">{facts.id}</span>. Remove
                  it from the clients file of the hub the device connects to, or it announces itself again.
                </>
              )
            ) : undefined
          }
          asksPassword
          onConfirm={() => {
            remove.mutate(device.id);
          }}
          onClose={() => {
            setOpen(false);
            if (remove.isSuccess) {
              window.location.hash = '#/';
              void remove.forget();
            }
          }}
        >
          <p>
            <strong>{displayName(device)}</strong> (<span className="mono">{facts.id}</span>) is removed from Hearth, and
            its MQTT user from this hub&apos;s clients file. To bring it back, give it a user again and restart the hub.
          </p>
        </ConfirmDialog>
      ) : null}
    </>
  );
}

function Section({ title, wide = false, children }: { title: string; wide?: boolean; children: ReactNode }) {
  return (
    <section className={wide ? 'panel-card card-wide' : 'panel-card'}>
      <h2 className="card-label">{title}</h2>
      {children}
    </section>
  );
}

function Row({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="kv">
      <span className="muted">{k}</span>
      <span>{v ?? '—'}</span>
    </div>
  );
}
