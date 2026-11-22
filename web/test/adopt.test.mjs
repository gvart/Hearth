// Adopting a host without an agent as a device. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { adoptedHosts, adoptPrefill, hostName, maxAdoptName, validAdoptName } from '../src/adopt.ts';

const host = (over) => ({
  mac: '00:11:32:00:00:05',
  ip: '192.168.2.50',
  hostname: '',
  vendor: '',
  device_id: '',
  state: '',
  name: '',
  ...over,
});

test('a host is called by its hostname, vendor or IP', () => {
  assert.equal(hostName(host({ hostname: 'lgtv.local', vendor: 'LG' })), 'lgtv');
  assert.equal(hostName(host({ vendor: 'LG' })), 'LG');
  assert.equal(hostName(host({})), '192.168.2.50');
});

test('the prompt starts with the host name, cut to the limit', () => {
  assert.equal(adoptPrefill(host({ hostname: 'printer.local' })), 'printer');
  const long = host({ hostname: 'é'.repeat(80) });
  assert.equal([...adoptPrefill(long)].length, maxAdoptName);
  assert.ok(validAdoptName(adoptPrefill(long)));
});

test('a name is 1 to 63 characters once trimmed, without control characters', () => {
  assert.ok(validAdoptName('Living room TV'));
  assert.ok(validAdoptName('  TV  '));
  assert.ok(validAdoptName('x'.repeat(63)));
  assert.ok(!validAdoptName(''));
  assert.ok(!validAdoptName('   '));
  assert.ok(!validAdoptName('x'.repeat(64)));
  assert.ok(!validAdoptName('T\nV'));
  assert.ok(!validAdoptName('T\u0007V'));
});

test('adopted hosts are listed by name, without enrolled devices', () => {
  const list = adoptedHosts([
    host({ mac: 'a', state: 'adopted', name: 'TV' }),
    host({ mac: 'b', state: 'known' }),
    host({ mac: 'c', state: 'adopted', name: 'Printer' }),
    host({ mac: 'd', state: 'adopted', name: 'Pi', device_id: 'pi' }),
  ]);
  assert.deepEqual(
    list.map((h) => h.mac),
    ['c', 'a'],
  );
});
