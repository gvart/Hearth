// Moving and zooming the network map. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bound, fit, maxZoom, minZoom, panBy, transformOf, zoomAt } from '../src/panzoom.ts';

const W = 1000;
const H = 600;
/** Where a point of the drawing lands in the box. */
const project = (v, x, y) => [v.k * x + v.x, v.k * y + v.y];

test('zooming keeps the point under the pointer where it is', () => {
  for (const [cx, cy] of [[500, 300], [0, 0], [900, 120]]) {
    const v = zoomAt(fit, 2, cx, cy, W, H);
    assert.equal(v.k, 2);
    // The drawing point that was under (cx, cy) before is still there.
    const [px, py] = project(v, cx, cy);
    assert.ok(Math.abs(px - cx) < 1e-9 && Math.abs(py - cy) < 1e-9, `${cx},${cy} moved to ${px},${py}`);
  }
});

test('zoom stops at its limits', () => {
  assert.equal(zoomAt(fit, 100, 500, 300, W, H).k, maxZoom);
  assert.equal(zoomAt(fit, 0.001, 500, 300, W, H).k, minZoom);
  let v = fit;
  for (let i = 0; i < 50; i++) {
    v = zoomAt(v, 1.25, 500, 300, W, H);
  }
  assert.equal(v.k, maxZoom);
});

test('zooming in and back out around one point returns to the fit', () => {
  const v = zoomAt(zoomAt(fit, 2, 400, 200, W, H), 0.5, 400, 200, W, H);
  assert.ok(Math.abs(v.k - 1) < 1e-9 && Math.abs(v.x) < 1e-9 && Math.abs(v.y) < 1e-9);
});

test('panning moves the drawing, and never out of reach', () => {
  assert.deepEqual(panBy(fit, 40, -25, W, H), { k: 1, x: 40, y: -25 });
  const far = panBy(fit, 1e6, 1e6, W, H);
  assert.deepEqual(far, { k: 1, x: 750, y: 450 });
  const back = panBy(fit, -1e6, -1e6, W, H);
  assert.deepEqual(back, { k: 1, x: -750, y: -450 });
  // Zoomed in, the far edge of the drawing can still be brought into the box.
  const zoomed = bound({ k: 4, x: -1e6, y: 0 }, W, H);
  assert.equal(zoomed.x, 250 - 4000);
});

test('transformOf writes the SVG transform', () => {
  assert.equal(transformOf(fit), 'translate(0.00 0.00) scale(1.0000)');
  assert.equal(transformOf({ k: 2, x: -10.5, y: 3 }), 'translate(-10.50 3.00) scale(2.0000)');
});
