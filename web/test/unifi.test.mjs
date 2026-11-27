// The UniFi model: where clients are connected, health lines. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bitRate, clientLink, healthDetail, validFingerprint } from '../src/unifi.ts';

test('clientLink names where a client is connected', () => {
  assert.equal(clientLink({ wired: true, uplink: 'Rack switch', port: 3 }), 'Wired · Rack switch · port 3');
  assert.equal(clientLink({ wired: true, uplink: '' }), 'Wired');
  assert.equal(clientLink({ wired: false, uplink: 'Living room AP', ssid: 'home' }), 'Wi-Fi · Living room AP · home');
  assert.equal(clientLink({ wired: false, uplink: '' }), 'Wi-Fi');
});

test('bitRate reads bytes per second as a link speed', () => {
  assert.equal(bitRate(0), '0 bit/s');
  assert.equal(bitRate(1000), '8 kbit/s');
  assert.equal(bitRate(2400000), '19.2 Mbit/s');
  assert.equal(bitRate(250000000), '2.0 Gbit/s');
});

test('healthDetail sums a subsystem up', () => {
  assert.equal(
    healthDetail({ subsystem: 'wan', status: 'ok', wan_ip: '203.0.113.7', isp: 'Example Fiber', rx_rate: 2400000, tx_rate: 120000 }),
    '203.0.113.7 · Example Fiber · ↓ 19.2 Mbit/s ↑ 960 kbit/s',
  );
  assert.equal(healthDetail({ subsystem: 'www', status: 'ok', latency_ms: 12 }), '12 ms');
  assert.equal(healthDetail({ subsystem: 'wlan', status: 'ok', users: 1 }), '1 client');
  assert.equal(healthDetail({ subsystem: 'vpn', status: 'unknown' }), '');
});

test('validFingerprint checks a SHA-256 fingerprint', () => {
  assert.equal(validFingerprint(''), true);
  assert.equal(validFingerprint(Array(32).fill('AB').join(':')), true);
  assert.equal(validFingerprint('AB:CD'), false);
});
