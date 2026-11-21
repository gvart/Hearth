// The sheet index and the command bar's search. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deviceHash, deviceOfHash, findCommands, pageOf, pagesOf, sheetOf, sheets } from '../src/nav.ts';

const devices = [
  { id: 'd1', name: 'pi5', hostname: 'pi5.lan', status: 'online' },
  { id: 'd2', name: 'nas', hostname: 'storage.lan', status: 'offline' },
  { id: 'd 3/x', name: 'talos-cp-1', hostname: 'talos-cp-1', status: 'online' },
];

test('every page belongs to one sheet and has its own link', () => {
  const pages = sheets.flatMap((s) => s.pages);
  assert.equal(new Set(pages.map((p) => p.id)).size, pages.length);
  assert.equal(new Set(pages.map((p) => p.hash)).size, pages.length);
  assert.deepEqual(sheets.map((s) => s.no), ['01', '02', '03', '04']);
});

test('pageOf reads the page from the hash', () => {
  const cases = [
    ['', 'devices'],
    ['#/', 'devices'],
    ['#/devices/d1', 'devices'],
    ['#/nothing-here', 'devices'],
    ['#/network', 'network'],
    ['#/kubernetes/homelab', 'kubernetes'],
    ['#/runbooks/run/42', 'runbooks'],
    ['#/approvals', 'approvals'],
    ['#/cluster', 'cluster'],
    ['#/settings', 'settings'],
  ];
  for (const [hash, page] of cases) {
    assert.equal(pageOf(hash), page, hash);
  }
  for (const p of sheets.flatMap((s) => s.pages)) {
    assert.equal(pageOf(p.hash), p.id);
  }
});

test('sheetOf finds the sheet of a page', () => {
  assert.equal(sheetOf('devices').id, 'lab');
  assert.equal(sheetOf('panels').id, 'automate');
  assert.equal(sheetOf('audit').id, 'activity');
  assert.equal(sheetOf('cluster').id, 'settings');
});

test('the Cluster page is listed on a cluster member, or while it is open', () => {
  const settings = sheetOf('settings');
  const ids = (opts) => pagesOf(settings, opts).map((p) => p.id);
  assert.ok(!ids({ cluster: false, current: 'settings' }).includes('cluster'));
  assert.ok(ids({ cluster: true, current: 'settings' }).includes('cluster'));
  assert.ok(ids({ cluster: false, current: 'cluster' }).includes('cluster'));
});

test('a device link round-trips its id', () => {
  for (const d of devices) {
    assert.equal(deviceOfHash(deviceHash(d.id)), d.id);
  }
  assert.equal(deviceOfHash('#/'), undefined);
  assert.equal(deviceOfHash('#/devices/'), undefined);
  assert.equal(deviceOfHash('#/devices/%E0%A4%A'), undefined);
});

test('findCommands finds pages and devices by every word', () => {
  const find = (q, cluster = true) => findCommands(q, devices, { cluster }).map((c) => `${c.kind}: ${c.label}`);
  assert.deepEqual(find(''), []);
  assert.deepEqual(find('   '), []);
  assert.deepEqual(find('net'), ['Go to: Network', 'Go to: Kubernetes']);
  assert.deepEqual(find('PI5'), ['Device: pi5']);
  assert.deepEqual(find('storage'), ['Device: nas']);
  assert.deepEqual(find('talos cp'), ['Device: talos-cp-1']);
  assert.deepEqual(find('automate run'), ['Go to: Runbooks']);
  assert.deepEqual(find('zzz'), []);
  assert.deepEqual(find('cluster'), ['Go to: Cluster']);
  assert.deepEqual(find('cluster', false), []);
});

test('a result links to its page or device, and names where it is', () => {
  const [page] = findCommands('audit', devices, { cluster: true });
  assert.deepEqual(page, { kind: 'Go to', label: 'Audit', hint: '03 Activity', hash: '#/audit' });
  const [device] = findCommands('nas', devices, { cluster: true });
  assert.deepEqual(device, { kind: 'Device', label: 'nas', hint: 'offline', hash: '#/devices/d2' });
  assert.ok(findCommands('a', devices, { cluster: true }).length <= 8);
});
