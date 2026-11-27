// The ESPHome model: entity states as text, discovered hosts. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { adoptedDevice, entityStateText, hostOf, isESPHomeHost, validKey } from '../src/esphome.ts';

test('entityStateText reads each kind of state', () => {
  assert.equal(entityStateText({ kind: 'sensor', state: 21.25, unit: '°C', accuracy_decimals: 1 }), '21.3 °C');
  assert.equal(entityStateText({ kind: 'sensor', state: 48, unit: '%' }), '48 %');
  assert.equal(entityStateText({ kind: 'sensor', state: null, unit: '%' }), 'Unknown');
  assert.equal(entityStateText({ kind: 'switch', state: true }), 'On');
  assert.equal(entityStateText({ kind: 'switch', state: false }), 'Off');
  assert.equal(entityStateText({ kind: 'binary_sensor', state: true, device_class: 'motion' }), 'Detected');
  assert.equal(entityStateText({ kind: 'binary_sensor', state: false, device_class: 'door' }), 'Closed');
  assert.equal(entityStateText({ kind: 'binary_sensor', state: true }), 'On');
  assert.equal(entityStateText({ kind: 'text_sensor', state: 'homelab' }), 'homelab');
  assert.equal(entityStateText({ kind: 'button', state: null }), '—');
});

test('isESPHomeHost and adoptedDevice find ESPHome hosts', () => {
  assert.equal(isESPHomeHost({ services: ['_http._tcp', '_esphomelib._tcp'] }), true);
  assert.equal(isESPHomeHost({ services: ['_http._tcp'] }), false);
  const devices = [
    { id: 'a', address: '192.168.1.40:6053' },
    { id: 'b', address: '[fe80::1]:6053' },
  ];
  assert.equal(adoptedDevice({ ip: '192.168.1.40' }, devices)?.id, 'a');
  assert.equal(adoptedDevice({ ip: 'fe80::1' }, devices)?.id, 'b');
  assert.equal(adoptedDevice({ ip: '192.168.1.4' }, devices), undefined);
  assert.equal(hostOf('10.0.0.2:7000'), '10.0.0.2');
});

test('validKey takes base64 of 32 bytes only', () => {
  assert.equal(validKey('px7tsbK3C7bpXHr2OevEV2ZMg/FrNBw2+O2pNPbedtA='), true);
  assert.equal(validKey(' px7tsbK3C7bpXHr2OevEV2ZMg/FrNBw2+O2pNPbedtA= '), true);
  assert.equal(validKey('c2hvcnQ='), false);
  assert.equal(validKey(''), false);
});
