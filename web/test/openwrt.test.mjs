// The OpenWrt model: clients, leases, connection checks. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { clientVia, isPlainHTTP, leaseLeft, validFingerprint } from '../src/openwrt.ts';

test('clientVia names where a client was learned', () => {
  assert.equal(clientVia({ lease: true, wireless: true, radio: 'phy0-ap0' }), 'Lease · Wi-Fi (phy0-ap0)');
  assert.equal(clientVia({ lease: true, wireless: false }), 'Lease');
  assert.equal(clientVia({ lease: false, wireless: true, radio: 'phy1-ap0' }), 'Wi-Fi (phy1-ap0)');
  assert.equal(clientVia({ lease: false, wireless: false }), '—');
});

test('leaseLeft reads what a lease has left', () => {
  assert.equal(leaseLeft({ lease: true, lease_expires: 0 }), 'Static');
  assert.equal(leaseLeft({ lease: true, lease_expires: 30 }), '1 min');
  assert.equal(leaseLeft({ lease: true, lease_expires: 1800 }), '30 min');
  assert.equal(leaseLeft({ lease: true, lease_expires: 43000 }), '12 h');
  assert.equal(leaseLeft({ lease: false, lease_expires: 0 }), '—');
});

test('validFingerprint and isPlainHTTP check a connection', () => {
  assert.equal(validFingerprint(''), true);
  assert.equal(validFingerprint('ab'.repeat(32)), true);
  assert.equal(validFingerprint(Array(32).fill('AB').join(':')), true);
  assert.equal(validFingerprint('AB:CD'), false);
  assert.equal(isPlainHTTP('http://192.168.1.1'), true);
  assert.equal(isPlainHTTP(' HTTP://router.lan'), true);
  assert.equal(isPlainHTTP('https://router.lan'), false);
});
