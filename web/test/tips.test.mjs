// The tips behind the "?" beside a page's title: short, and pointing at docs that exist. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { test } from 'node:test';
import { tips } from '../src/tips.ts';

test('every tip is short and its doc exists', () => {
  for (const [id, t] of Object.entries(tips)) {
    assert.ok(t.about.length > 0, `${id}: named`);
    assert.ok(t.lines.length >= 1 && t.lines.length <= 3, `${id}: one to three sentences`);
    assert.ok(t.lines.join(' ').length <= 460, `${id}: fits a small box`);
    if (t.docs) {
      assert.ok(existsSync(new URL(`../../docs/${t.docs}`, import.meta.url)), `${id}: docs/${t.docs} exists`);
    }
  }
});
