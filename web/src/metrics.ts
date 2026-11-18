/** A [unix milliseconds, value] pair of a metric series. */
export type MetricPoint = [number, number];

/** A metric value with its unit, for readouts. */
export function formatMetric(v: number, unit: string): string {
  switch (unit) {
    case 'percent':
      return `${v.toFixed(1)}%`;
    case 'celsius':
      return `${v.toFixed(1)} °C`;
    case 'bytes_per_second':
      return scaleRate(v, ['B/s', 'kB/s', 'MB/s', 'GB/s'], (n) => n.toPrecision(3));
    default:
      return v.toPrecision(3);
  }
}

/** A metric value in as few characters as possible, for axes and sparklines. */
export function formatMetricShort(v: number, unit: string): string {
  switch (unit) {
    case 'percent':
      return `${v.toFixed(0)}%`;
    case 'celsius':
      return `${v.toFixed(0)}°`;
    case 'bytes_per_second':
      return scaleRate(v, ['', 'k', 'M', 'G'], (n) => String(Number(n.toFixed(n < 10 ? 1 : 0))));
    default:
      return v.toPrecision(2);
  }
}

function scaleRate(v: number, units: string[], digits: (n: number) => string): string {
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  const unit = units[i] ?? '';
  return unit.endsWith('/s') ? `${digits(v)} ${unit}` : `${digits(v)}${unit}`;
}

/** The smallest of 1, 2 or 5 times a power of ten that is at least v. */
function niceCeil(v: number): number {
  if (v <= 0) {
    return 1;
  }
  const mag = 10 ** Math.floor(Math.log10(v));
  return ([1, 2, 5].find((m) => m * mag >= v) ?? 10) * mag;
}

/** The y axis of a series: percentages are always 0-100, so charts compare. */
export function yDomain(points: MetricPoint[], unit: string): [number, number] {
  if (unit === 'percent') {
    return [0, 100];
  }
  const values = points.map((p) => p[1]);
  if (unit === 'celsius' && values.length > 0) {
    return [Math.floor((Math.min(...values) - 5) / 10) * 10, Math.ceil((Math.max(...values) + 5) / 10) * 10];
  }
  return [0, niceCeil(Math.max(0, ...values))];
}

/** Splits a series where data is missing, so a line never bridges an outage. */
function segments(points: MetricPoint[]): MetricPoint[][] {
  const gaps = points.slice(1).map((p, i) => p[0] - (points[i]?.[0] ?? p[0]));
  const typical = gaps.slice().sort((a, b) => a - b)[Math.floor(gaps.length / 2)] ?? 0;
  const out: MetricPoint[][] = [];
  points.forEach((p, i) => {
    const gap = gaps[i - 1];
    const current = out.at(-1);
    if (current === undefined || (gap !== undefined && gap > typical * 3)) {
      out.push([p]);
    } else {
      current.push(p);
    }
  });
  return out;
}

/** Where a point sits in a plot, as fractions of its width and height from the top left. */
export function plotPosition(p: MetricPoint, start: number, end: number, domain: [number, number]): [number, number] {
  const clamp = (n: number) => Math.min(Math.max(n, 0), 1);
  return [clamp((p[0] - start) / (end - start || 1)), 1 - clamp((p[1] - domain[0]) / (domain[1] - domain[0] || 1))];
}

export interface PlotShapes {
  /** SVG points attributes of the connected runs of data. */
  lines: string[];
  areas: string[];
  /** SVG path data of the lone points, which a line cannot show. */
  dots: string;
}

/** The SVG shapes of a series in a width by height viewBox. */
export function plotShapes(
  points: MetricPoint[],
  start: number,
  end: number,
  domain: [number, number],
  width: number,
  height: number,
): PlotShapes {
  const shapes: PlotShapes = { lines: [], areas: [], dots: '' };
  for (const run of segments(points)) {
    const xy = run.map((p) => {
      const [x, y] = plotPosition(p, start, end, domain);
      return [(x * width).toFixed(1), (y * height).toFixed(1)] as const;
    });
    const first = xy[0];
    const last = xy.at(-1);
    if (first === undefined || last === undefined) {
      continue;
    }
    if (xy.length === 1) {
      shapes.dots += `M${first[0]} ${first[1]}h0.01`;
      continue;
    }
    const line = xy.map(([x, y]) => `${x},${y}`).join(' ');
    shapes.lines.push(line);
    shapes.areas.push(`${first[0]},${String(height)} ${line} ${last[0]},${String(height)}`);
  }
  return shapes;
}
