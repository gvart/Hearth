// The device page's Capabilities card: switches, lists, Docker's levels and
// when the hub asks for the password again. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  allLogs,
  allowsService,
  applied,
  capStates,
  cardMode,
  emptyCeiling,
  isPattern,
  parseList,
  raisesRisky,
  withDocker,
  withList,
  withPlugin,
  withSwitch,
} from '../src/capabilities.ts';

const caps = (over = {}) => ({
  hub: emptyCeiling(),
  local: emptyCeiling(),
  effective: emptyCeiling(),
  locked: false,
  manageable: true,
  agent_version: 'v1',
  ...over,
});

test('a switch turns a capability on as all of it, and off', () => {
  const on = withSwitch(emptyCeiling(), 'logs', true);
  assert.deepEqual(on.logs, allLogs);
  assert.deepEqual(withSwitch(on, 'logs', false).logs, []);
  assert.equal(withSwitch(emptyCeiling(), 'docker', true).docker_read, true);
  assert.equal(withSwitch(emptyCeiling(), 'docker', true).docker, false);
  assert.equal(withSwitch(emptyCeiling(), 'shell', true).shell, true);
  // Exec has no "on": a switch only turns it off.
  assert.deepEqual(withSwitch({ ...emptyCeiling(), exec: ['/a'] }, 'exec', true).exec, ['/a']);
  assert.deepEqual(withSwitch({ ...emptyCeiling(), exec: ['/a'] }, 'exec', false).exec, []);
});

test('a list is trimmed and deduplicated', () => {
  assert.deepEqual(parseList(' systemd:a.service,docker:web\n docker:web '), ['systemd:a.service', 'docker:web', 'docker:web']);
  assert.deepEqual(withList(emptyCeiling(), 'restart', ['docker:web', ' docker:web', '']).restart, ['docker:web']);
});

test('the password is asked for raising a terminal, programs, restarts or container control only', () => {
  const none = emptyCeiling();
  assert.equal(raisesRisky(none, withSwitch(none, 'shell', true)), true);
  assert.equal(raisesRisky(none, withList(none, 'exec', ['/usr/bin/df'])), true);
  assert.equal(raisesRisky(none, withSwitch(none, 'restart', true)), true);
  assert.equal(raisesRisky(none, withDocker(none, 'control')), true);
  assert.equal(raisesRisky(none, withDocker(none, 'read')), false);
  assert.equal(raisesRisky(none, withSwitch(none, 'logs', true)), false);
  assert.equal(raisesRisky(none, withSwitch(none, 'net_edges', true)), false);
  const all = { ...withSwitch(withSwitch(none, 'shell', true), 'restart', true), docker: true, exec: ['/a'] };
  assert.equal(raisesRisky(all, none), false, 'lowering never asks');
});

test('what a flag grants shows as set on the device', () => {
  const s = capStates(caps({ local: { ...emptyCeiling(), shell: true, logs: ['systemd:nginx.service'] } }));
  const shell = s.find((x) => x.info.key === 'shell');
  const logs = s.find((x) => x.info.key === 'logs');
  assert.equal(shell.local, true);
  assert.equal(shell.hubOn, false);
  assert.deepEqual(logs.localList, ['systemd:nginx.service']);
});

test('platforms without a capability say so', () => {
  const s = capStates(caps(), 'Microsoft Windows 11 Pro');
  assert.equal(s.find((x) => x.info.key === 'shell').unsupported, 'Not on Windows');
  assert.equal(capStates(caps(), 'darwin 26.1').find((x) => x.info.key === 'net_edges').unsupported, 'Linux only');
  assert.equal(capStates(caps(), 'debian 12').find((x) => x.info.key === 'net_edges').unsupported, undefined);
});

test('the card mode follows the agent', () => {
  assert.equal(cardMode(caps()), 'managed');
  assert.equal(cardMode(caps({ locked: true })), 'locked');
  assert.equal(cardMode(caps({ manageable: false })), 'upgrade');
  assert.equal(cardMode(caps({ effective: null })), 'unreported');
});

test('applied is false until the agent reports what was set', () => {
  const set = caps({ hub: withSwitch(emptyCeiling(), 'logs', true) });
  assert.equal(applied(set), false);
  assert.equal(applied({ ...set, effective: set.hub }), true);
  // An agent too old to take it never applies it: nothing to wait for.
  assert.equal(applied({ ...set, manageable: false }), true);
});

test('applied waits for a plugin grant too', () => {
  const hub = withPlugin(emptyCeiling(), 'go-lamp', 'safe');
  const set = caps({ hub, effective: emptyCeiling(), plugins_manageable: true });
  assert.equal(applied(set), false);
  assert.equal(applied({ ...set, effective: hub }), true);
  // The agent adds its own grant, at the higher class.
  const local = withPlugin(emptyCeiling(), 'go-lamp', 'dangerous');
  assert.equal(applied({ ...set, local, effective: hub }), false);
  assert.equal(applied({ ...set, local, effective: local }), true);
  // An agent too old for plugins never applies them.
  assert.equal(applied({ ...set, plugins_manageable: false }), true);
});

test('allowsService matches globs as the agent does', () => {
  assert.equal(allowsService(['docker:*'], 'docker:jellyfin'), true);
  assert.equal(allowsService(['docker:*'], 'systemd:jellyfin'), false);
  assert.equal(allowsService(['systemd:pihole-*'], 'systemd:pihole-FTL.service'), true);
  assert.equal(allowsService(['systemd:a.service'], 'systemd:a.service'), true);
  assert.equal(allowsService(['systemd:a.service'], 'systemd:aXservice'), false);
  assert.equal(isPattern('docker:*'), true);
  assert.equal(isPattern('docker:web'), false);
});

test('granting a plugin, or raising its class, asks for the password again', async () => {
  const { raisesRisky, withPlugin, withoutPlugin } = await import('../src/capabilities.ts');
  const none = emptyCeiling();
  const read = withPlugin(none, 'pi', 'read');
  assert.equal(raisesRisky(none, read), true);
  assert.equal(raisesRisky(read, withPlugin(read, 'pi', 'dangerous')), true);
  assert.equal(raisesRisky(withPlugin(read, 'pi', 'dangerous'), read), false);
  assert.equal(raisesRisky(read, withoutPlugin(read, 'pi')), false);
});

test('moving a plugin to a new release asks for the password again; a class change keeps the release', async () => {
  const { raisesRisky, withPlugin, withPluginRelease, newRelease } = await import('../src/capabilities.ts');
  const a = 'a'.repeat(64);
  const b = 'b'.repeat(64);
  const pinned = { ...emptyCeiling(), plugins: [{ name: 'pi', class: 'safe', digest: a }] };
  const lower = withPlugin(pinned, 'pi', 'read');
  assert.deepEqual(lower.plugins, [{ name: 'pi', class: 'read', digest: a }]);
  assert.equal(raisesRisky(pinned, lower), false);
  assert.equal(raisesRisky(pinned, withPluginRelease(pinned, 'pi', b)), true);
  const releases = [{ name: 'pi', version: '2.0.0', digest: b }];
  assert.equal(newRelease(pinned.plugins[0], releases)?.version, '2.0.0');
  assert.equal(newRelease({ name: 'pi', class: 'safe', digest: b }, releases), undefined);
});
