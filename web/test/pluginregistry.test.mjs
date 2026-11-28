// Settings → Plugins: search, what a plugin may do, and installed or update. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { accessLines, accessSummary, browseState, compareVersions, matches } from '../src/pluginregistry.ts';

const entry = (over = {}) => ({
  name: 'go-wasm-lamp',
  version: '1.0.0',
  description: 'A lamp over HTTP',
  author: 'Hearth',
  runtime: 'wasm',
  sha256: 'a'.repeat(64),
  memory: 32,
  capabilities: ['discover', 'state', 'command'],
  commands: [{ name: 'turn_on', class: 'safe' }],
  http_allow: ['192.168.1.40:80'],
  ...over,
});

test('matches searches the name, description and author', () => {
  assert.equal(matches(entry(), ''), true);
  assert.equal(matches(entry(), 'LAMP'), true);
  assert.equal(matches(entry(), 'over http'), true);
  assert.equal(matches(entry(), 'hearth'), true);
  assert.equal(matches(entry(), 'thermostat'), false);
});

test('accessLines lists every host the plugin may reach, or none', () => {
  assert.deepEqual(accessLines(entry()), [
    'Make HTTP requests to 192.168.1.40:80',
    'Use up to 32 MiB of memory',
    'Report devices and their entities to the hub',
  ]);
  assert.deepEqual(accessLines(entry({ http_allow: [], capabilities: ['command'], memory: 64 })), [
    'Reach nothing outside its sandbox: no network, no files',
    'Use up to 64 MiB of memory',
  ]);
  assert.equal(accessSummary(entry({ http_allow: ['a:80', 'b:443'] })), 'HTTP: a:80, b:443');
  assert.equal(accessSummary(entry({ http_allow: [] })), 'No network');
});

test('compareVersions orders semantic versions as the hub does', () => {
  const cases = [
    ['1.0.0', '1.0.0', 0],
    ['v1.0.0', '1.0.0', 0],
    ['1.0.1', '1.0.0', 1],
    ['1.10.0', '1.9.0', 1],
    ['1.0.0-rc.1', '1.0.0', -1],
    ['1.0.0-rc.10', '1.0.0-rc.9', 1],
    ['0.9.0', '1.0.0', -1],
  ];
  for (const [a, b, want] of cases) {
    assert.equal(compareVersions(a, b), want, `${a} vs ${b}`);
  }
});

test('browseState offers an install, an update, or nothing, never a downgrade', () => {
  const installed = (version) => [{ ...entry({ version }), source: 's', installed_at: '', installed_by: '' }];
  assert.equal(browseState(entry(), []), 'install');
  assert.equal(browseState(entry({ version: '1.1.0' }), installed('1.0.0')), 'update');
  assert.equal(browseState(entry(), installed('1.0.0')), 'installed');
  assert.equal(browseState(entry({ version: '0.9.0' }), installed('1.0.0')), 'installed');
});
