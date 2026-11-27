// The Integrations page's model: what is on, off, failing or only known on the hub. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { docsURL } from '../src/docs.ts';
import { integrationSummary, integrations } from '../src/integrations.ts';

const by = (list) => Object.fromEntries(list.map((i) => [i.id, i]));

test('with nothing set up, every integration is off or only known on the hub', () => {
  const list = integrations({});
  assert.deepEqual(
    list.map((i) => `${i.id}:${i.state}`),
    [
      'kubernetes:off',
      'proxmox:off',
      'esphome:off',
      'talos:off',
      'beszel:off',
      'plugins:off',
      'pihole:host',
      'dhcp:host',
      'netalertx:host',
      'prometheus:host',
      'mqtt:host',
    ],
  );
  assert.equal(integrationSummary(list), '0 on');
  assert.match(by(list).talos.detail, /--talosconfig/);
  assert.equal(new Set(list.map((i) => i.id)).size, list.length);
});

test('what is connected is on, with counts', () => {
  const i = by(
    integrations({
      clusters: [{ state: 'connected' }, { state: 'error' }],
      servers: [{ state: 'connected' }],
      talos: { status: 'ok', nodes: [1, 2, 3] },
      beszel: { status: 'connecting', systems: [] },
      plugins: [{ state: 'running' }, { state: 'stopped' }],
      hosts: [{ sources: ['scan', 'pihole'] }, { sources: ['pihole'] }, { sources: ['scan'] }],
    }),
  );
  assert.deepEqual([i.kubernetes.state, i.kubernetes.detail], ['on', '2 clusters connected, 1 unreachable']);
  assert.deepEqual([i.proxmox.state, i.proxmox.detail], ['on', '1 server connected']);
  assert.deepEqual([i.talos.state, i.talos.detail], ['on', '3 nodes']);
  assert.deepEqual([i.beszel.state, i.beszel.detail], ['on', 'Reading…']);
  assert.deepEqual([i.plugins.state, i.plugins.detail], ['on', '2 plugins, 1 running']);
  assert.deepEqual([i.pihole.state, i.pihole.detail], ['on', '2 hosts learned from it']);
  // No host learned from a source does not mean it is off: the API does not say.
  assert.equal(i.netalertx.state, 'host');
});

test('what is set up but cannot be read is failing, with the reason', () => {
  const list = integrations({
    clusters: [{ state: 'error' }],
    servers: [{ state: 'unavailable' }, { state: 'unavailable' }],
    talos: { status: 'unavailable', error: 'x509: certificate has expired', nodes: [] },
    beszel: { status: 'unavailable', systems: [] },
    plugins: [{ state: 'restarting' }],
  });
  const i = by(list);
  for (const id of ['kubernetes', 'proxmox', 'talos', 'beszel', 'plugins']) {
    assert.equal(i[id].state, 'trouble', id);
  }
  assert.equal(i.talos.detail, 'Cannot be read: x509: certificate has expired');
  assert.equal(i.beszel.detail, 'Cannot be read.');
  assert.equal(integrationSummary(list), '0 on · 5 failing');
});

test('docsURL points into the docs on GitHub', () => {
  assert.equal(docsURL('talos.md'), 'https://github.com/gvart/hearth/blob/main/docs/talos.md');
});
