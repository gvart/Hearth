// Device Protocol devices (docs/spec/device-protocol-v1.md): which devices
// are, what they announced, how their values read, and the params of a
// command. Kept apart from the components so node --test can check it
// (web/test/deviceprotocol.test.mjs).

/** The label the hub gives a device that has no agent, and its value for a Device Protocol device. */
export const sourceLabel = 'hearth.source';
export const deviceProtocolSource = 'device-protocol';

export type ProtocolEntityKind = 'sensor' | 'binary_sensor' | 'switch' | 'button';

export interface ProtocolEntity {
  id: string;
  kind: ProtocolEntityKind;
  name?: string;
  unit?: string;
}

export interface ProtocolCommandSpec {
  name: string;
  description?: string;
}

/** A state value: a boolean, number, string, or null while unknown. */
export type ProtocolValue = boolean | number | string | null;

/** What a Device Protocol device's facts hold, under "device_protocol". */
export interface ProtocolFacts {
  v: number;
  /** The device's protocol id: its MQTT username. */
  id: string;
  model?: string;
  manufacturer?: string;
  sw_version?: string;
  entities: ProtocolEntity[];
  commands: ProtocolCommandSpec[];
  state: Record<string, ProtocolValue | undefined>;
  telemetry: Record<string, number | undefined>;
  /** The policy class of device.command. */
  command_class: string;
  updated_at: string;
}

interface DeviceLike {
  labels: Record<string, string>;
  facts: unknown;
}

/** The device's Device Protocol facts, or undefined for any other device. */
export function protocolFacts(d: DeviceLike): ProtocolFacts | undefined {
  if (d.labels[sourceLabel] !== deviceProtocolSource) {
    return undefined;
  }
  // The lists and maps may be null on the wire.
  type Wire = Omit<ProtocolFacts, 'entities' | 'commands' | 'state' | 'telemetry'> & {
    [K in 'entities' | 'commands' | 'state' | 'telemetry']?: ProtocolFacts[K] | null;
  };
  const f = (d.facts as { device_protocol?: Wire } | null)?.device_protocol;
  if (!f) {
    return undefined;
  }
  return {
    ...f,
    entities: f.entities ?? [],
    commands: f.commands ?? [],
    state: f.state ?? {},
    telemetry: f.telemetry ?? {},
  };
}

export const protocolEntityKindLabel: Record<ProtocolEntityKind, string> = {
  sensor: 'Sensor',
  binary_sensor: 'Binary sensor',
  switch: 'Switch',
  button: 'Button',
};

/** An entity's latest value as text: "—" for a button or one not reported yet, "Unknown" for null. */
export function protocolValueText(e: Pick<ProtocolEntity, 'kind' | 'unit'>, v: ProtocolValue | undefined): string {
  if (e.kind === 'button' || v === undefined) {
    return '—';
  }
  if (v === null) {
    return 'Unknown';
  }
  if (typeof v === 'boolean') {
    return v ? 'On' : 'Off';
  }
  if (typeof v === 'number') {
    const text = Number.isInteger(v) ? String(v) : String(Math.round(v * 1000) / 1000);
    return e.unit ? `${text} ${e.unit}` : text;
  }
  return v;
}

/** The hub's limit on a command's params. */
export const maxParamsBytes = 4096;

export type ParsedParams = { ok: true; params: Record<string, unknown> | undefined } | { ok: false; error: string };

/** Reads a command's params as typed: empty is none, else a JSON object of at most 4 KiB. */
export function parseParams(text: string): ParsedParams {
  const t = text.trim();
  if (t === '') {
    return { ok: true, params: undefined };
  }
  if (new TextEncoder().encode(t).length > maxParamsBytes) {
    return { ok: false, error: 'Params may be at most 4 KiB.' };
  }
  let v: unknown;
  try {
    v = JSON.parse(t);
  } catch {
    return { ok: false, error: 'Params must be JSON, such as {"on": true}.' };
  }
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    return { ok: false, error: 'Params must be a JSON object, such as {"on": true}.' };
  }
  return { ok: true, params: v as Record<string, unknown> };
}
