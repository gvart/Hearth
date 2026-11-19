// Dashboard tokens: the Homepage snippet. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parse } from 'yaml';
import { homepageSnippet } from '../src/dashboard.ts';

test('homepageSnippet is a services.yaml group with a customapi widget', () => {
  const doc = parse(homepageSnippet('http://hub.lan:7080', 'SECRET'));
  const service = doc[0].Homelab[0].Hearth;
  assert.equal(service.href, 'http://hub.lan:7080/');
  assert.deepEqual(service.widget.headers, { Authorization: 'Bearer SECRET' });
  assert.equal(service.widget.type, 'customapi');
  assert.equal(service.widget.url, 'http://hub.lan:7080/api/v1/dashboard/summary');
  assert.deepEqual(
    service.widget.mappings.map((m) => m.field),
    ['counts.total', 'counts.online', 'counts.offline'],
  );
});
