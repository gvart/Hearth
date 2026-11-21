// The sheet index and the command bar's search. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  addDeviceHash,
  connectPlatformHash,
  deviceHash,
  deviceOfHash,
  findCommands,
  pageOf,
  pagesOf,
  planHash,
  planOfHash,
  sheetOf,
  sheets,
} from '../src/nav.ts';

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
    ['#/platforms', 'platforms'],
    ['#/platforms/kubernetes/homelab', 'platforms'],
    // Where the two lived before Platforms: old links still land there.
    ['#/kubernetes/homelab', 'platforms'],
    ['#/proxmox', 'platforms'],
    ['#/runbooks/run/42', 'runbooks'],
    ['#/approvals', 'approvals'],
    ['#/cluster', 'cluster'],
    ['#/settings', 'settings'],
    // The longest link wins: a page under #/settings is not General.
    ['#/settings/access', 'access'],
    ['#/settings/policy', 'policy'],
    ['#/settings/backup', 'backup'],
    ['#/settings/integrations', 'integrations'],
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
  const find = (q, cluster = true) => findCommands(q, { devices, cluster }).map((c) => `${c.kind}: ${c.label}`);
  assert.deepEqual(find(''), []);
  assert.deepEqual(find('   '), []);
  assert.deepEqual(find('net'), ['Go to: Network']);
  assert.deepEqual(find('plat'), ['Go to: Platforms', 'Run: Connect a platform']);
  assert.deepEqual(find('PI5'), ['Device: pi5']);
  assert.deepEqual(find('storage'), ['Device: nas']);
  assert.deepEqual(find('talos cp'), ['Device: talos-cp-1']);
  assert.deepEqual(find('automate run'), ['Go to: Runbooks']);
  assert.deepEqual(find('zzz'), []);
  // General is found as Settings: its own name says nothing in a list of results.
  assert.deepEqual(find('general'), ['Go to: Settings']);
  assert.deepEqual(find('integr'), ['Go to: Integrations']);
  assert.deepEqual(find('cluster'), ['Go to: Cluster']);
  assert.deepEqual(find('cluster', false), []);
});

test('a result links to its page or device, and names where it is', () => {
  const [page] = findCommands('audit', { devices, cluster: true });
  assert.deepEqual(page, { kind: 'Go to', label: 'Audit', hint: '03 Activity', hash: '#/audit' });
  const [device] = findCommands('nas', { devices, cluster: true });
  assert.deepEqual(device, { kind: 'Device', label: 'nas', hint: 'offline', hash: '#/devices/d2' });
  assert.ok(findCommands('a', { devices, cluster: true }).length <= 8);
});

test('findCommands finds platforms and runbooks, after pages and devices', () => {
  const src = {
    devices,
    cluster: true,
    platforms: [{ name: 'homelab', kind: 'Kubernetes cluster', hash: '#/platforms/kubernetes/c1' }],
    runbooks: [{ id: 'upgrade-talos-node', description: 'One node at a time' }, { id: 'rotate-backups' }],
  };
  assert.deepEqual(findCommands('homelab', src), [
    { kind: 'Platform', label: 'homelab', hint: 'Kubernetes cluster', hash: '#/platforms/kubernetes/c1' },
  ]);
  assert.deepEqual(
    findCommands('talos', src).map((c) => `${c.kind}: ${c.label}`),
    ['Device: talos-cp-1', 'Runbook: upgrade-talos-node'],
  );
  // A runbook opens at its plan: the command bar never starts a run.
  const [backups] = findCommands('rotate', src);
  assert.deepEqual(backups, { kind: 'Runbook', label: 'rotate-backups', hint: 'Plan and start', hash: '#/runbooks/plan/rotate-backups' });
  assert.equal(planOfHash(planHash('a b/c')), 'a b/c');
  assert.equal(planOfHash('#/runbooks/plan/'), undefined);
  assert.equal(planOfHash('#/runbooks'), undefined);
  assert.equal(pageOf(planHash('x')), 'runbooks');
});

test('findCommands offers what the UI itself can run', () => {
  const run = (q, extra = {}) =>
    findCommands(q, { devices: [], cluster: false, ...extra }).filter((c) => c.kind === 'Run');
  assert.deepEqual(run('add'), [{ kind: 'Run', label: 'Add a device', hint: 'Enrollment command', hash: addDeviceHash }]);
  assert.deepEqual(run('connect')[0].hash, connectPlatformHash);
  assert.equal(pageOf(addDeviceHash), 'devices');
  assert.equal(pageOf(connectPlatformHash), 'platforms');
  // The other theme is offered, and only when the theme in use is known.
  assert.deepEqual(run('theme'), []);
  assert.deepEqual(run('theme', { theme: 'blueprint' }), [
    { kind: 'Run', label: 'Switch theme to Paper', hint: 'This browser', theme: 'paper' },
  ]);
  assert.equal(run('theme', { theme: 'paper' })[0].theme, 'blueprint');
  // A runbook can be written in the UI only on a hub that keeps its configuration in the store.
  assert.deepEqual(run('new runbook'), []);
  assert.equal(run('new runbook', { editable: true })[0].hash, '#/runbooks/new');
});
