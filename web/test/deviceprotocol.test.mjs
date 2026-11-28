// The Device Protocol model: which devices are protocol devices, how their values read,
// and a command's params. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseParams, protocolFacts, protocolValueText } from '../src/deviceprotocol.ts';

test('protocolFacts reads a protocol device and nothing else', () => {
  const facts = { device_protocol: { v: 1, id: 'kitchen', entities: null, commands: [{ name: 'restart' }], state: null } };
  const f = protocolFacts({ labels: { 'hearth.source': 'device-protocol' }, facts });
  assert.equal(f?.id, 'kitchen');
  assert.deepEqual(f?.entities, []);
  assert.deepEqual(f?.state, {});
  assert.deepEqual(f?.telemetry, {});
  assert.equal(f?.commands[0].name, 'restart');
  // An agent's device, even with such facts, and a protocol label without them.
  assert.equal(protocolFacts({ labels: {}, facts }), undefined);
  assert.equal(protocolFacts({ labels: { 'hearth.source': 'device-protocol' }, facts: {} }), undefined);
  assert.equal(protocolFacts({ labels: { 'hearth.source': 'device-protocol' }, facts: null }), undefined);
});

test('protocolValueText reads each kind of value', () => {
  assert.equal(protocolValueText({ kind: 'sensor', unit: '°C' }, 21.5), '21.5 °C');
  assert.equal(protocolValueText({ kind: 'sensor', unit: '°C' }, 21.123456), '21.123 °C');
  assert.equal(protocolValueText({ kind: 'sensor' }, 3), '3');
  assert.equal(protocolValueText({ kind: 'sensor' }, 'idle'), 'idle');
  assert.equal(protocolValueText({ kind: 'sensor' }, null), 'Unknown');
  assert.equal(protocolValueText({ kind: 'sensor' }, undefined), '—');
  assert.equal(protocolValueText({ kind: 'switch' }, true), 'On');
  assert.equal(protocolValueText({ kind: 'binary_sensor' }, false), 'Off');
  assert.equal(protocolValueText({ kind: 'button' }, true), '—');
});

test('parseParams takes nothing or a JSON object', () => {
  assert.deepEqual(parseParams(''), { ok: true, params: undefined });
  assert.deepEqual(parseParams('  \n'), { ok: true, params: undefined });
  assert.deepEqual(parseParams('{"on": true}'), { ok: true, params: { on: true } });
  for (const bad of ['{', 'true', '[1]', 'null', '"x"']) {
    assert.equal(parseParams(bad).ok, false, bad);
  }
  const big = parseParams(JSON.stringify({ s: 'x'.repeat(5000) }));
  assert.equal(big.ok, false);
  assert.match(big.ok ? '' : big.error, /4 KiB/);
});
