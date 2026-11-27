// ESPHome devices: how their entities read, and which discovered hosts are
// ESPHome devices. Kept apart from the components so node --test can check
// it (web/test/esphome.test.mjs).

import type { ESPHomeDevice, ESPHomeEntity, ESPHomeEntityKind } from './api/esphome.ts';

/** The mDNS service type an ESPHome device with the native API announces. */
export const esphomeService = '_esphomelib._tcp';

export const entityKindLabel: Record<ESPHomeEntityKind, string> = {
  sensor: 'Sensor',
  binary_sensor: 'Binary sensor',
  switch: 'Switch',
  button: 'Button',
  text_sensor: 'Text sensor',
};

/** An entity's state as text: the value with its unit, on or off, the text; "—" while it has none. */
export function entityStateText(e: Pick<ESPHomeEntity, 'kind' | 'state' | 'unit' | 'accuracy_decimals' | 'device_class'>): string {
  if (e.kind === 'button') {
    return '—';
  }
  if (e.state === null) {
    return 'Unknown';
  }
  if (typeof e.state === 'boolean') {
    if (e.kind === 'binary_sensor') {
      return binaryText(e.device_class ?? '', e.state);
    }
    return e.state ? 'On' : 'Off';
  }
  if (typeof e.state === 'number') {
    const text = e.state.toFixed(Math.min(Math.max(e.accuracy_decimals ?? 0, 0), 10));
    return e.unit ? `${text} ${e.unit}` : text;
  }
  return e.state;
}

/** What a binary sensor's state means for its device class, as Home Assistant words it. */
function binaryText(deviceClass: string, on: boolean): string {
  switch (deviceClass) {
    case 'motion':
    case 'occupancy':
    case 'presence':
      return on ? 'Detected' : 'Clear';
    case 'door':
    case 'window':
    case 'opening':
    case 'garage_door':
      return on ? 'Open' : 'Closed';
    case 'connectivity':
      return on ? 'Connected' : 'Disconnected';
    case 'problem':
      return on ? 'Problem' : 'OK';
  }
  return on ? 'On' : 'Off';
}

/** Whether a discovered host announces the ESPHome native API. */
export function isESPHomeHost(h: { services: string[] }): boolean {
  return h.services.includes(esphomeService);
}

/** The adopted device a discovered host is, by its IP; undefined when none. */
export function adoptedDevice(h: { ip: string }, devices: Pick<ESPHomeDevice, 'id' | 'address'>[]) {
  return devices.find((d) => hostOf(d.address) === h.ip);
}

/** The IP of an address as the hub stores it: 192.168.1.40:6053, [fe80::1]:6053. */
export function hostOf(address: string): string {
  const i = address.lastIndexOf(':');
  const host = i < 0 ? address : address.slice(0, i);
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

/** Whether a key looks like an API encryption key: base64 of 32 bytes. */
export function validKey(key: string): boolean {
  return /^[A-Za-z0-9+/]{43}=$/.test(key.trim());
}
