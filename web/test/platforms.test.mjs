// The Platforms page's model: links, cards and the summary. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { platformCards, platformHash, platformOfHash, platformSummary } from '../src/platforms.ts';

const clusters = [
  { id: 'c1', name: 'homelab', server: 'https://10.0.0.10:6443', state: 'connected', error: '', nodes: 3, pods: 41 },
  { id: 'c2', name: 'edge', server: 'https://10.0.9.1:6443', state: 'error', error: 'dial tcp: timeout', nodes: 0, pods: 0 },
];
const servers = [
  { id: 's1', name: 'pve', url: 'https://pve.lan:8006', state: 'connected', error: '', nodes: 1, guests: 9 },
  { id: 's2', name: 'attic', url: 'https://attic.lan:8006', state: 'connecting', error: '', nodes: 0, guests: 0 },
];

test('platformHash and platformOfHash round-trip, and refuse anything else', () => {
  assert.equal(platformHash('kubernetes', 'c1'), '#/platforms/kubernetes/c1');
  assert.deepEqual(platformOfHash(platformHash('proxmox', 'a b/c')), { kind: 'proxmox', id: 'a b/c' });
  for (const hash of ['', '#/platforms', '#/platforms/', '#/platforms/talos/x', '#/platforms/proxmox/', '#/platforms/proxmox/a/b', '#/platforms/proxmox/%E0%A4%A', '#/kubernetes/c1']) {
    assert.equal(platformOfHash(hash), undefined, hash);
  }
});

test('platformCards lists every platform, the unreachable first', () => {
  const cards = platformCards(clusters, servers);
  assert.deepEqual(
    cards.map((c) => `${c.kind}:${c.name}:${c.state}`),
    ['kubernetes:edge:unreachable', 'proxmox:attic:connecting', 'kubernetes:homelab:connected', 'proxmox:pve:connected'],
  );
  const homelab = cards.find((c) => c.name === 'homelab');
  assert.equal(homelab.line, '3 nodes · 41 pods');
  assert.equal(homelab.address, 'https://10.0.0.10:6443');
  assert.equal(homelab.hash, '#/platforms/kubernetes/c1');
  assert.equal(cards.find((c) => c.name === 'pve').line, '1 host · 9 guests');
  assert.equal(cards[0].error, 'dial tcp: timeout');
});

test('platformSummary counts what is connected and what cannot be reached', () => {
  assert.equal(platformSummary([]), 'None connected yet');
  assert.equal(platformSummary(platformCards(clusters, servers)), '4 connected · 1 unreachable');
  assert.equal(platformSummary(platformCards([], servers)), '2 connected');
});

test('an ESPHome device is a platform card, read-only unless calls are allowed', () => {
  const cards = platformCards([], [], [
    { id: 'e1', name: 'kitchen', address: '192.168.1.40:6053', state: 'connected', error: '', entities: 5, control: false },
    { id: 'e2', name: 'porch', address: '192.168.1.41:6053', state: 'unavailable', error: 'the device rejected the encryption key', entities: 0, control: true },
  ]);
  assert.deepEqual(
    cards.map((c) => [c.name, c.state, c.line, c.hash]),
    [
      ['porch', 'unreachable', '0 entities · calls allowed', '#/platforms/esphome/e2'],
      ['kitchen', 'connected', '5 entities · read-only', '#/platforms/esphome/e1'],
    ],
  );
  assert.deepEqual(platformOfHash('#/platforms/esphome/e1'), { kind: 'esphome', id: 'e1' });
});

test('an OpenWrt router is a platform card counting its clients', () => {
  const cards = platformCards([], [], [], [
    { id: 'o1', name: 'gateway', url: 'https://192.168.1.1:443', state: 'connected', error: '', clients: 14 },
    { id: 'o2', name: 'attic', url: 'http://192.168.1.2:80', state: 'unavailable', error: 'the router refused the username or password', clients: 0 },
  ]);
  assert.deepEqual(
    cards.map((c) => [c.name, c.state, c.line, c.hash]),
    [
      ['attic', 'unreachable', '0 clients', '#/platforms/openwrt/o2'],
      ['gateway', 'connected', '14 clients', '#/platforms/openwrt/o1'],
    ],
  );
  assert.deepEqual(platformOfHash('#/platforms/openwrt/o1'), { kind: 'openwrt', id: 'o1' });
});

test('an OPNsense firewall is a platform card counting its clients', () => {
  const cards = platformCards([], [], [], [], [
    { id: 'f1', name: 'edge', url: 'https://192.168.1.1:443', state: 'connected', error: '', clients: 6 },
    { id: 'f2', name: 'lab', url: 'https://10.0.0.1:443', state: 'unavailable', error: 'the firewall refused the API key or secret', clients: 0 },
  ]);
  assert.deepEqual(
    cards.map((c) => [c.name, c.state, c.line, c.hash]),
    [
      ['lab', 'unreachable', '0 clients', '#/platforms/opnsense/f2'],
      ['edge', 'connected', '6 clients', '#/platforms/opnsense/f1'],
    ],
  );
  assert.deepEqual(platformOfHash('#/platforms/opnsense/f1'), { kind: 'opnsense', id: 'f1' });
});
