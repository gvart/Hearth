// Stylesheets read design tokens and hold no literal of their own. Run with `npm test` in web/.
// See src/styles/README.md.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';

const src = new URL('../src/', import.meta.url);
const read = (rel) => readFileSync(new URL(rel, src), 'utf8');
const strip = (css) => css.replace(/\/\*[\s\S]*?\*\//g, '');

const tokens = strip(read('styles/tokens.css'));
const sheets = ['index.css', 'styles/blueprint.css'].concat(
  readdirSync(new URL('components/', src))
    .filter((f) => f.endsWith('.css'))
    .map((f) => `components/${f}`),
);

/** Every declaration of a stylesheet, as [property, value]. */
function declarations(css) {
  return [...strip(css).matchAll(/([\w-]+)\s*:\s*([^;{}]+);/g)].map((m) => [m[1].toLowerCase(), m[2].replace(/\s+/g, ' ').trim()]);
}

const defined = new Set([...tokens.matchAll(/--([\w-]+)\s*:/g)].map((m) => m[1]));

test('tokens.css defines both themes with the same colours', () => {
  const block = (sel) => tokens.slice(tokens.indexOf(sel)).split('}')[0];
  const names = (b) => [...b.matchAll(/--([\w-]+)\s*:/g)].map((m) => m[1]).sort();
  const blueprint = names(block("[data-theme='blueprint']"));
  assert.ok(blueprint.includes('bg') && blueprint.includes('accent'));
  assert.deepEqual(names(block("[data-theme='paper']")), blueprint);
});

for (const sheet of sheets) {
  test(`${sheet} holds no colour of its own`, () => {
    for (const [prop, value] of declarations(read(sheet))) {
      assert.doesNotMatch(value, /#[0-9a-f]{3,8}\b|\brgba?\(|\bhsla?\(|color-mix\(/i, `${prop}: ${value}`);
    }
  });

  test(`${sheet} reads only tokens that exist`, () => {
    for (const [prop, value] of declarations(read(sheet))) {
      assert.ok(!prop.startsWith('--') || prop === '--sheet', `${prop} is declared outside tokens.css`);
      for (const m of value.matchAll(/var\(--([\w-]+)/g)) {
        assert.ok(defined.has(m[1]), `${prop}: ${value} reads --${m[1]}, which tokens.css does not define`);
      }
    }
  });

  test(`${sheet} takes spacing, type, corners, lines and timing from tokens`, () => {
    const scaled = /^(gap|row-gap|column-gap|padding|margin|font-size|font-weight|border-radius|border|outline|transition|animation)/;
    for (const [prop, value] of declarations(read(sheet))) {
      if (!scaled.test(prop)) {
        continue;
      }
      assert.doesNotMatch(value, /(?<![\w.(-])-?\d*\.?\d+(px|rem|em|ms|s)\b/, `${prop}: ${value}`);
      if (prop === 'font-weight') {
        assert.doesNotMatch(value, /^\d+$/, `${prop}: ${value}`);
      }
    }
  });
}
