// A runbook step as a form: its values as fields, and edits that change one
// value and leave every other byte of the file, comments included, as it was.
// Kept apart from the components so node --test can check it
// (web/test/runbookfields.test.mjs).

import { isMap, isScalar, isSeq, parseDocument, type Document, type Node, type Scalar } from 'yaml';

export interface StepField {
  /** Where the value is in the step: "action.device", "action.command.0". */
  path: string;
  /** The key it is set under, which names it and finds its help: "device". */
  key: string;
  /** The key, with its place in a list when it is one of several: "command 1". */
  label: string;
  /** The keys above it, for a heading: "action". */
  group: string;
  value: string;
  /** block: a value of several lines (| or >), edited in a text area. */
  kind: 'line' | 'block';
}

interface Found extends StepField {
  node: Scalar;
}

/** A scalar's value as text; nothing for one that holds none. */
const asText = (v: unknown): string => (typeof v === 'string' ? v : typeof v === 'number' || typeof v === 'boolean' ? String(v) : '');

const isBlock = (n: Scalar) => n.type === 'BLOCK_LITERAL' || n.type === 'BLOCK_FOLDED';

/** A scalar as its field shows it: an unquoted one as written (200, true, 2m), any other as its text. */
function shown(n: Scalar, source: string): string {
  if (isBlock(n)) {
    return asText(n.value).replace(/\n+$/, '');
  }
  if (n.type === 'PLAIN' && n.range) {
    return source.slice(n.range[0], n.range[1]);
  }
  return asText(n.value);
}

function stepOf(doc: Document, index: number): Node | undefined {
  const steps = doc.get('steps', true);
  return isSeq(steps) ? (steps.items[index] as Node | undefined) : undefined;
}

function walk(node: unknown, path: string[], key: string, label: string, source: string, out: Found[]): void {
  if (isScalar(node)) {
    out.push({
      path: path.join('.'),
      key,
      label,
      group: path.slice(0, -1 - (/^\d+$/.test(path[path.length - 1] ?? '') ? 1 : 0)).join(' · '),
      value: shown(node, source),
      kind: isBlock(node) ? 'block' : 'line',
      node,
    });
  } else if (isMap(node)) {
    for (const pair of node.items) {
      if (isScalar(pair.key)) {
        const k = String(pair.key.value);
        walk(pair.value, [...path, k], k, k, source, out);
      }
    }
  } else if (isSeq(node)) {
    node.items.forEach((item, i) => {
      walk(item, [...path, String(i)], key, `${key} ${String(i + 1)}`, source, out);
    });
  }
}

function find(source: string, index: number): { fields: Found[]; errors: number } {
  const doc = parseDocument(source);
  const out: Found[] = [];
  walk(stepOf(doc, index), [], '', '', source, out);
  return { fields: out, errors: doc.errors.length };
}

/** The values of one step, in the order the file has them. Empty when the file does not parse that far. */
export function fieldsOf(source: string, index: number): StepField[] {
  return find(source, index).fields.map(({ path, key, label, group, value, kind }) => ({ path, key, label, group, value, kind }));
}

/**
 * The ways to write a value in place of a scalar, the one closest to how it was
 * written first. A block's source ends with its line break; a value that
 * replaces the block with something else keeps that break after it.
 */
function candidates(node: Scalar, old: string, value: string): { written: string; tail: string }[] {
  const quoted = JSON.stringify(value);
  if (isBlock(node)) {
    const tail = old.endsWith('\n') ? '\n' : '';
    // Keep the header (| or >, with its chomping) and the indent of the lines under it.
    const [header = '|-', ...rest] = old.split('\n');
    const indent = /^ */.exec(rest.find((l) => l.trim() !== '') ?? '')?.[0] ?? '';
    if (value === '' || indent === '') {
      return [{ written: quoted, tail }];
    }
    const lines = value.split('\n').map((l) => (l === '' ? '' : indent + l));
    return [
      { written: `${header}\n${lines.join('\n')}\n`, tail: '' },
      { written: quoted, tail },
    ];
  }
  const plain = (written: string) => ({ written, tail: '' });
  if (value.includes('\n') || node.type === 'QUOTE_DOUBLE') {
    return [plain(quoted)];
  }
  if (node.type === 'QUOTE_SINGLE') {
    return [plain(`'${value.replace(/'/g, "''")}'`), plain(quoted)];
  }
  return value === '' ? [plain(quoted)] : [plain(value), plain(quoted)];
}

/**
 * The file with one value of one step changed. Only the value's own characters
 * are replaced. It is written the way it was (unquoted, quoted, a block) when
 * that reads back as the same value in the same place, and in double quotes
 * otherwise; undefined when not even that leaves the rest of the file as it was.
 */
export function setField(source: string, index: number, path: string, value: string): string | undefined {
  const before = find(source, index);
  const at = before.fields.findIndex((f) => f.path === path);
  const field = before.fields[at];
  const range = field?.node.range;
  if (!field || !range) {
    return undefined;
  }
  const want = field.kind === 'block' ? value.replace(/\n+$/, '') : value.trim();
  if (want === field.value) {
    return source;
  }
  const [start, end] = range;
  for (const { written, tail } of candidates(field.node, source.slice(start, end), want)) {
    const text = source.slice(0, start) + written + tail + source.slice(end);
    const after = find(text, index);
    const now = after.fields[at];
    // The same fields in the same places, this one holding exactly what was written, and nothing new wrong.
    if (
      after.errors <= before.errors &&
      after.fields.length === before.fields.length &&
      after.fields.every((f, i) => f.path === before.fields[i]?.path) &&
      now?.node.range?.[0] === start &&
      now.node.range[1] === start + written.length &&
      now.value === want
    ) {
      return text;
    }
  }
  return undefined;
}

/** A step's lines in the file, counted from 1, as analyze() reports them. */
export interface StepLines {
  line: number;
  endLine: number;
}

/** Whether a file still reads as a runbook with these step ids, in this order. */
function reads(text: string, ids: string[]): boolean {
  const doc = parseDocument(text);
  const steps = doc.get('steps', true);
  if (doc.errors.length > 0) {
    return false;
  }
  const got = isSeq(steps) ? steps.items.map((s) => (isMap(s) ? asText(s.get('id')) : '')) : [];
  return got.length === ids.length && got.every((id, i) => id === ids[i]);
}

const idsOf = (source: string): string[] => {
  const steps = parseDocument(source).get('steps', true);
  return isSeq(steps) ? steps.items.map((s) => (isMap(s) ? asText(s.get('id')) : '')) : [];
};

/**
 * Each step's own lines, for cutting and moving. Unlike analyze(), which gives
 * a step every line up to the next one, the comment lines right above a step
 * belong to that step: they are about it, and travel with it.
 */
function blocks(source: string, steps: StepLines[]): { lines: string[]; at: StepLines[] } {
  const lines = source.split('\n');
  const indentOf = (n: number) => /^ */.exec(lines[n - 1] ?? '')?.[0].length ?? 0;
  const at = steps.map((s) => ({ ...s }));
  at.forEach((b, i) => {
    const floor = (steps[i - 1]?.line ?? b.line - 1) + 1;
    const dash = indentOf(b.line);
    while (b.line > floor && /^\s*#/.test(lines[b.line - 2] ?? '') && indentOf(b.line - 1) === dash) {
      b.line--;
    }
  });
  at.forEach((b, i) => {
    const next = at[i + 1];
    if (next) {
      b.endLine = next.line - 1;
      while (b.endLine > b.line && (lines[b.endLine - 1] ?? '').trim() === '') {
        b.endLine--;
      }
    }
  });
  return { lines, at };
}

/**
 * The file without one step: its lines are cut, the comment right above it
 * and the blank lines after it with them. undefined when what is left would
 * not read as the same runbook less that step (a step written on the "steps:"
 * line, say), so nothing is cut by guesswork.
 */
export function removeStep(source: string, steps: StepLines[], index: number): string | undefined {
  const { lines, at } = blocks(source, steps);
  const s = at[index];
  if (!s) {
    return undefined;
  }
  const end = at[index + 1] ? (at[index + 1]?.line ?? 1) - 1 : s.endLine;
  const text = [...lines.slice(0, s.line - 1), ...lines.slice(end)].join('\n');
  const ids = idsOf(source);
  ids.splice(index, 1);
  return reads(text, ids) ? text : undefined;
}

/**
 * The file with one step moved one place up (-1) or down (1): the two steps'
 * lines change places, each with the comment right above it, and the blank
 * lines between them stay between them. undefined at either end of the list,
 * or when the result would not read as the same steps in the new order.
 */
export function moveStep(source: string, steps: StepLines[], index: number, by: -1 | 1): string | undefined {
  const { lines, at } = blocks(source, steps);
  const lo = Math.min(index, index + by);
  const first = at[lo];
  const second = at[lo + 1];
  if (!first || !second || lo < 0) {
    return undefined;
  }
  const a = lines.slice(first.line - 1, first.endLine);
  const gap = lines.slice(first.endLine, second.line - 1);
  const b = lines.slice(second.line - 1, second.endLine);
  const text = [...lines.slice(0, first.line - 1), ...b, ...gap, ...a, ...lines.slice(second.endLine)].join('\n');
  const ids = idsOf(source);
  [ids[lo], ids[lo + 1]] = [ids[lo + 1] ?? '', ids[lo] ?? ''];
  return reads(text, ids) ? text : undefined;
}
