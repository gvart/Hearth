// Moving and zooming a drawing inside its box: the network map uses it. A view maps a point of the
// drawing to the box as  box = k * drawing + (x, y), all in the drawing's own units. Kept apart
// from the component so node --test can check it (web/test/panzoom.test.mjs).

export interface View {
  k: number;
  x: number;
  y: number;
}

/** The whole drawing, as laid out. */
export const fit: View = { k: 1, x: 0, y: 0 };

export const minZoom = 0.5;
export const maxZoom = 6;

const clamp = (v: number, lo: number, hi: number) => Math.min(Math.max(v, lo), hi);

/**
 * Keeps the drawing reachable: zoomed within its limits, and never dragged so
 * far that less than a quarter of the box still shows it.
 */
export function bound(v: View, width: number, height: number): View {
  const k = clamp(v.k, minZoom, maxZoom);
  return {
    k,
    x: clamp(v.x, width * 0.25 - width * k, width * 0.75),
    y: clamp(v.y, height * 0.25 - height * k, height * 0.75),
  };
}

/** Zooms by a factor, keeping the point (cx, cy) of the box where it is. */
export function zoomAt(v: View, factor: number, cx: number, cy: number, width: number, height: number): View {
  const k = clamp(v.k * factor, minZoom, maxZoom);
  const f = k / v.k;
  return bound({ k, x: cx - (cx - v.x) * f, y: cy - (cy - v.y) * f }, width, height);
}

/** Moves the drawing by (dx, dy). */
export function panBy(v: View, dx: number, dy: number, width: number, height: number): View {
  return bound({ k: v.k, x: v.x + dx, y: v.y + dy }, width, height);
}

/** The SVG transform of a view. */
export function transformOf(v: View): string {
  return `translate(${v.x.toFixed(2)} ${v.y.toFixed(2)}) scale(${v.k.toFixed(4)})`;
}
