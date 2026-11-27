// The OPNsense model: clients, leases, firmware. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { clientVia, firmwareLine, isPlainHTTP, leaseLeft } from '../src/opnsense.ts';

test('clientVia names where a client was learned', () => {
  assert.equal(clientVia({ lease: true, lease_source: 'dnsmasq', arp: true, ipv6: ['fd00::23'] }), 'Dnsmasq lease · ARP · NDP');
  assert.equal(clientVia({ lease: true, lease_source: 'kea', arp: false, ipv6: [] }), 'Kea lease');
  assert.equal(clientVia({ lease: true, lease_source: 'isc', arp: false, ipv6: [] }), 'ISC DHCP lease');
  assert.equal(clientVia({ lease: false, lease_source: '', arp: true, ipv6: [] }), 'ARP');
  assert.equal(clientVia({ lease: false, lease_source: '', arp: false, ipv6: [] }), '—');
});

test('leaseLeft reads what a lease has left', () => {
  const now = 1_795_000_000;
  assert.equal(leaseLeft({ lease: true, static: true, lease_ends: 0 }, now), 'Static');
  assert.equal(leaseLeft({ lease: true, static: false, lease_ends: 0 }, now), 'Active');
  assert.equal(leaseLeft({ lease: true, static: false, lease_ends: now + 30 }, now), '1 min');
  assert.equal(leaseLeft({ lease: true, static: false, lease_ends: now + 1800 }, now), '30 min');
  assert.equal(leaseLeft({ lease: true, static: false, lease_ends: now + 43000 }, now), '12 h');
  assert.equal(leaseLeft({ lease: true, static: false, lease_ends: now + 7 * 86400 }, now), '7 d');
  assert.equal(leaseLeft({ lease: true, static: false, lease_ends: now - 5 }, now), 'Ended');
  assert.equal(leaseLeft({ lease: false, static: false, lease_ends: 0 }, now), '—');
});

test('firmwareLine says what the last update check found', () => {
  const f = { product: 'OPNsense', version: '25.7.4', latest: '25.7.5', status: 'update', message: '' };
  assert.equal(firmwareLine(f), 'OPNsense 25.7.4 · 25.7.5 available');
  assert.equal(firmwareLine({ ...f, status: 'none', latest: '25.7.4' }), 'OPNsense 25.7.4');
  assert.equal(firmwareLine({ ...f, status: 'error' }), 'OPNsense 25.7.4 · update check failed');
  assert.equal(firmwareLine({ ...f, version: '' }), '');
});

test('isPlainHTTP spots a URL Hearth refuses', () => {
  assert.equal(isPlainHTTP('http://192.168.1.1'), true);
  assert.equal(isPlainHTTP(' HTTP://opnsense.lan'), true);
  assert.equal(isPlainHTTP('https://opnsense.lan'), false);
});
