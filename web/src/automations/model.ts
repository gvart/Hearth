// The visual editor's view of an automation file. The YAML text is the only
// state: the model is read from it, and every edit replaces only the source
// ranges it changes, so comments, key order, the text of every other value and
// anything the editor cannot show stay byte for byte as they were. No React
// here: test/ runs this under Node.

import { isAlias, isCollection, isMap, isPair, isScalar, isSeq, parseDocument, Scalar, stringify, visit } from 'yaml';
import type { Document, Node as YamlNode, Pair, YAMLMap, YAMLSeq } from 'yaml';
import schema from './schema.json' with { type: 'json' };

export type FieldKind = 'text' | 'multiline' | 'number' | 'bool' | 'select' | 'duration' | 'list' | 'map';

export interface FieldSpec {
  key: string;
  label: string;
  kind: FieldKind;
  required?: boolean;
  options?: string[];
  help?: string;
}

export interface StepSpec {
  label: string;
  fields: FieldSpec[];
}

export type Section = 'triggers' | 'conditions' | 'actions';

export const sections: Section[] = ['triggers', 'conditions', 'actions'];

export const stepSpecs = schema as unknown as Record<Section, Record<string, StepSpec | undefined>>;

/** A field's value: text for scalars, a list, or a map's entries in order. */
export type FieldValue = string | boolean | string[] | [string, string][];

/** Part of a file the editor shows as written and never changes. */
export interface ReadOnlyYaml {
  yaml: string;
  reason: string;
}

export interface StepBlock {
  kind: 'step';
  index: number;
  type: string;
  spec: StepSpec;
  id: string;
  description: string;
  values: Partial<Record<string, FieldValue>>;
  /** Keys of this step the form cannot show. */
  extras: ReadOnlyYaml[];
}

export interface RawBlock extends ReadOnlyYaml {
  kind: 'raw';
  index: number;
}

export type Block = StepBlock | RawBlock;

export interface AutomationModel {
  id: string;
  description: string;
  mode: string;
  blocks: Record<Section, Block[]>;
  /** A whole section the editor cannot show, such as an alias. */
  rawSections: Partial<Record<Section, ReadOnlyYaml>>;
  /** Top-level keys the editor cannot show. */
  extras: ReadOnlyYaml[];
}

export interface YamlProblem {
  line: number;
  message: string;
}

export type ParseResult =
  | { ok: true; model: AutomationModel }
  /** With yamlOnly the file is fine, but the form could misrepresent it. */
  | { ok: false; problems: YamlProblem[]; yamlOnly?: boolean };

const rootKeys = ['id', 'description', 'mode', ...sections];

/** Characters the hub reads as line breaks, and this editor's parser does not. */
const hiddenBreak = /[\u0085\u2028\u2029]/;

function lineOf(source: string, offset: number): number {
  return source.slice(0, offset).split('\n').length;
}

function parse(source: string): Document.Parsed {
  return parseDocument(source, { prettyErrors: false });
}

/**
 * Why this file can only be edited as text, if it can: the form would show
 * something other than what the hub runs, or an edit could change what an alias
 * means.
 */
export function yamlOnlyReason(source: string): string | undefined {
  const hidden = hiddenBreak.exec(source);
  if (hidden) {
    const code = (hidden[0].codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0');
    return `Line ${String(lineOf(source, hidden.index))} holds the invisible character U+${code}, which the hub reads as a line break, so the hub may run steps the visual view would not show. Use the YAML view, and remove the character to get the visual view back.`;
  }
  const doc = parse(source);
  if (doc.errors.length > 0) {
    return undefined;
  }
  const seen = new Set<string>();
  let repeated: string | undefined;
  visit(doc, {
    Node(_, node) {
      const { anchor } = node as { anchor?: string };
      if (anchor !== undefined && seen.has(anchor)) {
        repeated = anchor;
        return visit.BREAK;
      }
      if (anchor !== undefined) {
        seen.add(anchor);
      }
      return undefined;
    },
  });
  return repeated === undefined
    ? undefined
    : `The anchor &${repeated} is defined more than once, so moving or removing a step could change what its aliases mean. Use the YAML view, and give each anchor its own name to get the visual view back.`;
}

/** The text of a node's range, with the indentation of its first line removed. */
function slice(source: string, start: number, end: number): string {
  const indent = start - (source.lastIndexOf('\n', start - 1) + 1);
  const strip = new RegExp(`^ {0,${String(indent)}}`);
  return source
    .slice(start, end)
    .trimEnd()
    .split('\n')
    .map((line, i) => (i === 0 ? line : line.replace(strip, '')))
    .join('\n');
}

function nodeText(source: string, node: unknown): string {
  const range = (node as YamlNode).range;
  return range ? slice(source, range[0], range[1]) : '';
}

function pairText(source: string, pair: Pair): string {
  const start = (pair.key as YamlNode).range?.[0] ?? 0;
  const value = pair.value as YamlNode | null;
  const end = value?.range?.[1] ?? (pair.key as YamlNode).range?.[1] ?? start;
  return slice(source, start, end);
}

/** Anchors, aliases, merge keys and tags mean more than the form can say. */
function usesYamlFeatures(node: unknown): boolean {
  let found = false;
  visit(node as YamlNode, {
    Alias() {
      found = true;
      return visit.BREAK;
    },
    Node(_, n) {
      if (n.anchor !== undefined || (n.tag !== undefined && !n.tag.startsWith('tag:yaml.org,2002:'))) {
        found = true;
        return visit.BREAK;
      }
      return undefined;
    },
    Pair(_, p) {
      if (isScalar(p.key) && p.key.value === '<<') {
        found = true;
        return visit.BREAK;
      }
      return undefined;
    },
  });
  return found;
}

/** A string the form can show. An escaped line break stays as it is written. */
function stringOf(node: unknown): string | undefined {
  return isScalar(node) && typeof node.value === 'string' && !hiddenBreak.test(node.value) ? node.value : undefined;
}

/** Lists and maps are edited as lines, which are trimmed: padding would be lost. */
function isLineValue(s: string): boolean {
  return !s.includes('\n') && s === s.trim();
}

/** The form's value of a node, or undefined if the form cannot show it. */
function readField(spec: FieldSpec, node: unknown): FieldValue | undefined {
  switch (spec.kind) {
    case 'number':
      // 010 is 8 to the hub and 10 here: such a number is left as it is written.
      return isScalar(node) && typeof node.value === 'number' && plainNumber.test(node.source ?? '')
        ? node.source
        : undefined;
    case 'bool':
      return isScalar(node) && typeof node.value === 'boolean' ? node.value : undefined;
    case 'multiline':
      return stringOf(node);
    case 'text':
    case 'duration':
    case 'select': {
      const s = stringOf(node);
      return s?.includes('\n') ? undefined : s;
    }
    case 'list': {
      if (!isSeq(node)) {
        return undefined;
      }
      const items = node.items.map(stringOf);
      return items.every((s): s is string => s !== undefined && isLineValue(s) && s !== '') ? items : undefined;
    }
    case 'map': {
      if (!isMap(node)) {
        return undefined;
      }
      const entries: [string, string][] = [];
      for (const pair of node.items) {
        const key = stringOf(pair.key);
        const value = stringOf(pair.value);
        if (key === undefined || value === undefined || key === '' || key.includes(':')) {
          return undefined;
        }
        if (!isLineValue(key) || !isLineValue(value)) {
          return undefined;
        }
        entries.push([key, value]);
      }
      return entries;
    }
  }
}

function readBlock(source: string, section: Section, item: unknown, index: number): Block {
  const raw = (reason: string): RawBlock => ({ kind: 'raw', index, yaml: nodeText(source, item), reason });
  if (!isMap(item)) {
    return raw('This step is not a mapping.');
  }
  if (usesYamlFeatures(item)) {
    return raw('This step uses YAML anchors, aliases or tags.');
  }
  const type = stringOf(item.get('type', true));
  if (type === undefined) {
    return raw('This step has no type.');
  }
  const spec = stepSpecs[section][type];
  if (!spec) {
    return raw(
      section === 'conditions'
        ? 'The hub has no condition types yet, so it refuses this file until the condition is removed.'
        : `The editor has no form for the type "${type}".`,
    );
  }
  const block: StepBlock = { kind: 'step', index, type, spec, id: '', description: '', values: {}, extras: [] };
  for (const pair of item.items) {
    const key = stringOf(pair.key);
    if (key === 'type') {
      continue;
    }
    if (key === 'id' || key === 'description') {
      const value = stringOf(pair.value);
      if (value !== undefined && !value.includes('\n')) {
        block[key] = value;
        continue;
      }
    }
    const field = spec.fields.find((f) => f.key === key);
    const value = field ? readField(field, pair.value) : undefined;
    if (field && value !== undefined) {
      block.values[field.key] = value;
    } else {
      block.extras.push({
        yaml: pairText(source, pair),
        reason: field ? 'The form cannot show this value.' : 'The form has no field for this key.',
      });
    }
  }
  return block;
}

/** Reads a file into the visual model, or says why it cannot be shown. */
export function readAutomation(source: string): ParseResult {
  const yamlOnly = yamlOnlyReason(source);
  if (yamlOnly !== undefined) {
    return { ok: false, yamlOnly: true, problems: [{ line: 0, message: yamlOnly }] };
  }
  const doc = parse(source);
  if (doc.errors.length > 0) {
    return {
      ok: false,
      problems: doc.errors.map((e) => ({ line: lineOf(source, e.pos[0]), message: e.message })),
    };
  }
  const root = doc.contents;
  if (!isMap(root)) {
    return { ok: false, problems: [{ line: 1, message: 'An automation must be a mapping.' }] };
  }
  const model: AutomationModel = {
    id: '',
    description: '',
    mode: '',
    blocks: { triggers: [], conditions: [], actions: [] },
    rawSections: {},
    extras: [],
  };
  for (const pair of root.items) {
    const key = stringOf(pair.key);
    const text = () => pairText(source, pair);
    if (key === 'id' || key === 'description' || key === 'mode') {
      const value = stringOf(pair.value);
      if (value !== undefined && !value.includes('\n') && !usesYamlFeatures(pair.value)) {
        model[key] = value;
      } else {
        model.extras.push({ yaml: text(), reason: 'The form cannot show this value.' });
      }
    } else if (key === 'triggers' || key === 'conditions' || key === 'actions') {
      if (isSeq(pair.value) && pair.value.anchor === undefined) {
        // A step using an anchor or alias is read-only on its own.
        model.blocks[key] = pair.value.items.map((item, i) => readBlock(source, key, item, i));
      } else {
        model.rawSections[key] = { yaml: text(), reason: 'This section is not a list of steps.' };
      }
    } else {
      model.extras.push({ yaml: text(), reason: 'The hub does not know this key.' });
    }
  }
  return { ok: true, model };
}

/** Where a field lives: the top of the file, or a step of a section. */
export type StepRef = { section: Section; index: number } | null;

function refuse(why: string): Error {
  return new Error(`${why} Make this change in the YAML view.`);
}

/** A value as the hub must read it: text as written is kept for what is not a string. */
type Raw = string | Raw[] | RawMap;
interface RawMap {
  [key: string]: Raw;
}

function rawOf(node: unknown): Raw {
  if (isMap(node)) {
    const out = Object.create(null) as RawMap;
    for (const pair of node.items) {
      out[String(isScalar(pair.key) ? pair.key.value : pair.key)] = rawOf(pair.value);
    }
    return out;
  }
  if (isSeq(node)) {
    return node.items.map(rawOf);
  }
  if (isScalar(node)) {
    return typeof node.value === 'string' ? `s:${node.value}` : `r:${node.source ?? String(node.value)}`;
  }
  return isAlias(node) ? `a:${node.source}` : 'r:';
}

function canon(raw: Raw): unknown {
  if (typeof raw === 'string') {
    return raw;
  }
  if (Array.isArray(raw)) {
    return raw.map(canon);
  }
  return ['map', ...Object.keys(raw).sort().map((key) => [key, canon(raw[key] ?? '')])];
}

interface Splice {
  from: number;
  to: number;
  text: string;
}

/** One edit: the replacements of the source, and how the file must then read. */
interface EditState {
  source: string;
  root: YAMLMap;
  tree: RawMap;
  splices: Splice[];
}

function applySplices(source: string, splices: Splice[]): string {
  // Stable: text inserted at one place stays in the order it was added.
  const ordered = splices.map((s, i) => ({ ...s, i })).sort((a, b) => a.from - b.from || a.i - b.i);
  let out = '';
  let at = 0;
  for (const { from, to, text } of ordered) {
    if (from < at) {
      throw refuse('This edit overlaps itself.');
    }
    out += source.slice(at, from) + text;
    at = to;
  }
  return out + source.slice(at);
}

/**
 * Runs an edit on the source text: only the replaced ranges change, so every
 * other byte stays as written. The result must read as the edit intended, down
 * to the text of each number, or the edit is refused.
 */
function edit(source: string, change: (state: EditState) => void): string {
  const yamlOnly = yamlOnlyReason(source);
  if (yamlOnly !== undefined) {
    throw new Error(yamlOnly);
  }
  const doc = parse(source);
  if (doc.errors.length > 0) {
    throw new Error('the file does not parse');
  }
  const root = doc.contents;
  if (!isMap(root)) {
    throw new Error('the file is not a mapping');
  }
  const state: EditState = { source, root, tree: rawOf(root) as RawMap, splices: [] };
  change(state);
  if (state.splices.length === 0) {
    return source;
  }
  const written = applySplices(source, state.splices);
  const after = parse(written);
  if (after.errors.length > 0 || JSON.stringify(canon(rawOf(after.contents))) !== JSON.stringify(canon(state.tree))) {
    throw refuse('This edit cannot be written without changing something else in the file.');
  }
  return written;
}

function targetMap(root: YAMLMap, ref: StepRef): YAMLMap {
  if (ref === null) {
    return root;
  }
  const seq = root.get(ref.section, true);
  const item: unknown = isSeq(seq) ? seq.items[ref.index] : undefined;
  if (!isMap(item)) {
    throw new Error('no such step');
  }
  return item;
}

function treeAt(tree: RawMap, ref: StepRef): RawMap {
  return ref === null ? tree : ((tree[ref.section] as Raw[])[ref.index] as RawMap);
}

function rangeOf(node: unknown): [number, number] {
  const range = (node as YamlNode | null)?.range;
  if (!range) {
    throw refuse('This part of the file has no position.');
  }
  return [range[0], range[1]];
}

function lineStart(source: string, pos: number): number {
  return pos === 0 ? 0 : source.lastIndexOf('\n', pos - 1) + 1;
}

function columnOf(source: string, pos: number): number {
  return pos - lineStart(source, pos);
}

function nextLine(source: string, pos: number): number {
  const newline = source.indexOf('\n', pos);
  return newline === -1 ? source.length : newline + 1;
}

/** Where a node's own text ends, before any comment lines that follow it. */
function contentEnd(node: unknown): number {
  if (isCollection(node) && !node.flow && node.items.length > 0) {
    const last: unknown = node.items[node.items.length - 1];
    if (isPair(last)) {
      const value = last.value as YamlNode | null;
      return value?.range ? Math.max(contentEnd(value), rangeOf(last.key)[1]) : rangeOf(last.key)[1];
    }
    return contentEnd(last);
  }
  return rangeOf(node)[1];
}

/** The start of the line after a node, which ends a block scalar already. */
function endOfLines(source: string, node: unknown): number {
  const end = contentEnd(node);
  return source[end - 1] === '\n' ? end : nextLine(source, end);
}

function indentOf(source: string): number {
  const m = /^( +)\S/m.exec(source);
  return m?.[1] ? Math.min(m[1].length, 8) : 2;
}

/** Whether a list under a key is indented, as `triggers:\n  - x`. */
function indentsSequences(source: string): boolean {
  return !/^[\w-]+:[^\n]*\n(?:\s*#[^\n]*\n)*- /m.test(source);
}

type Wanted = string | boolean | { number: string };

function leafOf(wanted: Wanted): string {
  if (typeof wanted === 'string') {
    return `s:${wanted}`;
  }
  return `r:${typeof wanted === 'boolean' ? String(wanted) : wanted.number}`;
}

function isWanted(node: Scalar, wanted: Wanted): boolean {
  if (typeof wanted === 'object') {
    return node.source === wanted.number;
  }
  return node.value === wanted;
}

/** Text the hub and this editor both read as this very string, on one line. */
function plainText(value: string, flow: boolean): string {
  const quoted = JSON.stringify(value);
  if (/[\n\r\t]/.test(value) || (flow && /[,[\]{}]/.test(value))) {
    return quoted;
  }
  const written = stringify(value, { lineWidth: 0 }).trimEnd();
  if (written.includes('\n')) {
    return quoted;
  }
  if (written !== value) {
    return written;
  }
  // The hub's parser follows YAML 1.1, where more words are not strings.
  const strict = parseDocument(value, { version: '1.1' }).contents;
  const isText = isScalar(strict) && strict.value === value && !/^[-+]?[\d.][\d_.,:eE+-]*$/.test(value);
  return isText ? value : quoted;
}

/** A multi-line string as a block scalar whose body starts at this column. */
function blockText(value: string, column: number): string | undefined {
  if (/\r/.test(value) || /^[ \t\n]/.test(value) || /[ \t]\n/.test(value)) {
    return undefined;
  }
  const body = value.replace(/\n+$/, '');
  const tail = value.length - body.length;
  const chomp = tail === 0 ? '-' : tail === 1 ? '' : '+';
  const pad = ' '.repeat(column);
  const lines = value.slice(0, tail > 1 ? value.length - 1 : body.length).split('\n');
  return `|${chomp}\n${lines.map((line) => (line === '' ? '' : pad + line)).join('\n')}`;
}

function scalarText(wanted: Wanted, existing: Scalar | null, flow: boolean, column: number, step: number): string {
  if (typeof wanted === 'boolean') {
    return String(wanted);
  }
  if (typeof wanted === 'object') {
    return wanted.number;
  }
  const type = existing?.type;
  if (type === Scalar.QUOTE_DOUBLE) {
    return JSON.stringify(wanted);
  }
  if (type === Scalar.QUOTE_SINGLE && !/[\n\r\t]/.test(wanted)) {
    return `'${wanted.replaceAll("'", "''")}'`;
  }
  if (wanted.includes('\n') && !flow) {
    return blockText(wanted, column + step) ?? JSON.stringify(wanted);
  }
  return plainText(wanted, flow);
}

/** Replaces a scalar in place. A comment after it stays in its column. */
function replaceScalar(state: EditState, node: Scalar, flow: boolean, wanted: Wanted, column: number) {
  const { source, splices } = state;
  const isBlock = node.type === Scalar.BLOCK_LITERAL || node.type === Scalar.BLOCK_FOLDED;
  if (isBlock && node.comment) {
    throw refuse('This text has a comment on its first line.');
  }
  const [from, to] = rangeOf(node);
  let text = scalarText(wanted, node, flow, column, indentOf(source));
  if (from === to && source[from - 1] === ':') {
    text = ` ${text}`;
  }
  if (source[to - 1] === '\n') {
    splices.push({ from, to, text: `${text}\n` });
    return;
  }
  const gap = /^ +(?=#)/.exec(source.slice(to))?.[0].length;
  if (gap === undefined || text.includes('\n')) {
    splices.push({ from, to, text });
    return;
  }
  const shift = text.length - (to - from);
  splices.push({ from, to: to + gap, text: text + ' '.repeat(Math.max(1, gap - shift)) });
}

function findPair(map: YAMLMap, key: string): Pair | undefined {
  return map.items.find((p) => stringOf(p.key) === key);
}

function flowItemText(source: string, item: unknown): string {
  if (isPair(item)) {
    const value = item.value as YamlNode | null;
    const end = value?.range ? Math.max(value.range[1], rangeOf(item.key)[1]) : rangeOf(item.key)[1];
    return source.slice(rangeOf(item.key)[0], end);
  }
  const [from, to] = rangeOf(item);
  return source.slice(from, to);
}

/** Rewrites a one-line flow collection from the text of its items. */
function writeFlow(state: EditState, node: YAMLMap | YAMLSeq, parts: string[]) {
  const [from, to] = rangeOf(node);
  const text = state.source.slice(from, to);
  const open = text[0] ?? '';
  const close = text[text.length - 1] ?? '';
  if (text.includes('\n') || !'[{'.includes(open) || !']}'.includes(close)) {
    throw refuse('This list is written over several lines.');
  }
  const pad = text[1] === ' ' && parts.length > 0 ? ' ' : '';
  state.splices.push({ from, to, text: `${open}${pad}${parts.join(', ')}${pad}${close}` });
}

/** Adds whole lines at the start of a line, or at the end of the file. */
function insertLines(state: EditState, at: number, text: string) {
  const open = at === state.source.length && !state.source.endsWith('\n');
  state.splices.push({ from: at, to: at, text: open ? `\n${text}` : `${text}\n` });
}

/** Adds `key: value` after the nearest key that comes before it in order. */
function insertPair(state: EditState, map: YAMLMap, key: string, text: string, order: string[]) {
  const { source } = state;
  const at = order.indexOf(key);
  const orderOf = (p: Pair) => order.indexOf(stringOf(p.key) ?? '');
  const previous = at === -1 ? [] : map.items.filter((p) => orderOf(p) !== -1 && orderOf(p) < at);
  const later = at === -1 ? undefined : map.items.find((p) => orderOf(p) > at);
  const anchor = previous[previous.length - 1];
  if (map.flow) {
    const parts = map.items.map((p) => flowItemText(source, p));
    const index = anchor ? map.items.indexOf(anchor) + 1 : later ? map.items.indexOf(later) : parts.length;
    parts.splice(index, 0, text);
    writeFlow(state, map, parts);
    return;
  }
  const first = map.items[0];
  if (!first) {
    throw refuse('This mapping is empty.');
  }
  const column = columnOf(source, rangeOf(first.key)[0]);
  if (!anchor && later) {
    const from = rangeOf(later.key)[0];
    state.splices.push({ from, to: from, text: `${text}\n${' '.repeat(column)}` });
    return;
  }
  const after = anchor ?? map.items[map.items.length - 1];
  const end = after?.value ? endOfLines(source, after.value) : nextLine(source, rangeOf(after?.key)[1]);
  insertLines(state, end, ' '.repeat(column) + text);
}

function removePair(state: EditState, map: YAMLMap, pair: Pair) {
  const { source, splices } = state;
  if (map.flow) {
    writeFlow(state, map, map.items.filter((p) => p !== pair).map((p) => flowItemText(source, p)));
    return;
  }
  const start = rangeOf(pair.key)[0];
  const lineFrom = lineStart(source, start);
  const end = pair.value ? endOfLines(source, pair.value) : nextLine(source, rangeOf(pair.key)[1]);
  if (source.slice(lineFrom, start).trim() === '') {
    splices.push({ from: lineFrom, to: end, text: '' });
    return;
  }
  // The first key of a step shares its line with the dash: the next key moves up.
  const next = map.items[map.items.indexOf(pair) + 1];
  if (!next || source.slice(end, rangeOf(next.key)[0]).trim() !== '') {
    throw refuse('This key cannot be removed from its step here.');
  }
  splices.push({ from: start, to: rangeOf(next.key)[0], text: '' });
}

/** The dash of a block list's item, which must be first on its line. */
function dashOf(source: string, item: unknown): number {
  let at = rangeOf(item)[0] - 1;
  while (at >= 0 && (source[at] === ' ' || source[at] === '\n')) {
    at -= 1;
  }
  if (source[at] !== '-' || source.slice(lineStart(source, at), at).trim() !== '') {
    throw refuse('This step is not written as a plain list item.');
  }
  return at;
}

function setScalar(state: EditState, ref: StepRef, key: string, wanted: Wanted, order: string[]) {
  const { source } = state;
  const map = targetMap(state.root, ref);
  const pair = findPair(map, key);
  treeAt(state.tree, ref)[key] = leafOf(wanted);
  if (!pair) {
    const column = map.items[0] ? columnOf(source, rangeOf(map.items[0].key)[0]) : 0;
    const text = scalarText(wanted, null, map.flow === true, column, indentOf(source));
    insertPair(state, map, key, `${plainText(key, map.flow === true)}: ${text}`, order);
    return;
  }
  if (!isScalar(pair.value)) {
    throw refuse(`The value of ${key} is not a single value.`);
  }
  if (!isWanted(pair.value, wanted)) {
    replaceScalar(state, pair.value, map.flow === true, wanted, columnOf(source, rangeOf(pair.key)[0]));
  }
}

function setList(state: EditState, ref: StepRef, key: string, items: string[], order: string[]) {
  const { source, splices } = state;
  const map = targetMap(state.root, ref);
  const pair = findPair(map, key);
  treeAt(state.tree, ref)[key] = items.map(leafOf);
  if (!pair) {
    const text = `[${items.map((item) => plainText(item, true)).join(', ')}]`;
    insertPair(state, map, key, `${plainText(key, map.flow === true)}: ${text}`, order);
    return;
  }
  const seq = pair.value;
  if (!isSeq(seq)) {
    throw refuse(`The value of ${key} is not a list.`);
  }
  if (seq.flow) {
    const parts = items.map((item, i) => {
      const node: unknown = seq.items[i];
      if (isScalar(node) && node.value === item) {
        return flowItemText(source, node);
      }
      return scalarText(item, isScalar(node) ? node : null, true, 0, 0);
    });
    writeFlow(state, seq, parts);
    return;
  }
  const last: unknown = seq.items[seq.items.length - 1];
  if (last === undefined) {
    throw refuse(`${key} has no items.`);
  }
  const dash = dashOf(source, last);
  const column = columnOf(source, dash);
  seq.items.forEach((node: unknown, i) => {
    const item = items[i];
    if (item === undefined) {
      const from = lineStart(source, dashOf(source, node));
      splices.push({ from, to: endOfLines(source, node), text: '' });
    } else if (!isScalar(node)) {
      throw refuse(`An item of ${key} is not a single value.`);
    } else if (node.value !== item) {
      replaceScalar(state, node, false, item, column);
    }
  });
  const end = endOfLines(source, last);
  for (const item of items.slice(seq.items.length)) {
    insertLines(state, end, `${' '.repeat(column)}- ${plainText(item, false)}`);
  }
}

function setEntries(state: EditState, ref: StepRef, key: string, entries: [string, string][], order: string[]) {
  const { source } = state;
  const map = targetMap(state.root, ref);
  const pair = findPair(map, key);
  const raw = Object.create(null) as RawMap;
  for (const [k, v] of entries) {
    raw[k] = leafOf(v);
  }
  treeAt(state.tree, ref)[key] = raw;
  if (!pair) {
    const parts = entries.map(([k, v]) => `${plainText(k, true)}: ${plainText(v, true)}`);
    insertPair(state, map, key, `${plainText(key, map.flow === true)}: {${parts.join(', ')}}`, order);
    return;
  }
  const target = pair.value;
  if (!isMap(target)) {
    throw refuse(`The value of ${key} is not a mapping.`);
  }
  if (target.flow) {
    const parts = entries.map(([k, v]) => {
      const had = findPair(target, k);
      if (had && isScalar(had.value) && had.value.value === v) {
        return flowItemText(source, had);
      }
      const existing = had && isScalar(had.value) ? had.value : null;
      return `${plainText(k, true)}: ${scalarText(v, existing, true, 0, 0)}`;
    });
    writeFlow(state, target, parts);
    return;
  }
  for (const had of target.items) {
    if (!entries.some(([k]) => k === stringOf(had.key))) {
      removePair(state, target, had);
    }
  }
  for (const [k, v] of entries) {
    const had = findPair(target, k);
    if (!had) {
      insertPair(state, target, k, `${plainText(k, false)}: ${plainText(v, false)}`, []);
    } else if (!isScalar(had.value)) {
      throw refuse(`The value of ${k} is not a single value.`);
    } else if (had.value.value !== v) {
      replaceScalar(state, had.value, false, v, columnOf(source, rangeOf(had.key)[0]));
    }
  }
}

function isEmpty(value: FieldValue | undefined): boolean {
  return value === undefined || value === '' || (Array.isArray(value) && value.length === 0);
}

/** Numbers the hub and this editor read alike. */
const plainNumber = /^-?(0|[1-9]\d*)(\.\d+)?$/;

function applyField(state: EditState, ref: StepRef, field: FieldSpec | string, value: FieldValue | undefined) {
  const typed = typeof value === 'string' ? [value] : Array.isArray(value) ? value.flat() : [];
  if (typed.some((text) => hiddenBreak.test(text))) {
    throw new Error('This text holds an invisible character the hub reads as a line break. Remove it and try again.');
  }
  const map = targetMap(state.root, ref);
  const key = typeof field === 'string' ? field : field.key;
  const kind = typeof field === 'string' ? 'text' : field.kind;
  let order = rootKeys;
  if (ref !== null) {
    const spec = stepSpecs[ref.section][stringOf(map.get('type', true)) ?? ''];
    order = ['id', 'type', 'description', ...(spec?.fields.map((f) => f.key) ?? [])];
  }
  if (isEmpty(value)) {
    const pair = findPair(map, key);
    if (pair) {
      removePair(state, map, pair);
      Reflect.deleteProperty(treeAt(state.tree, ref), key);
    }
  } else if (kind === 'list') {
    setList(state, ref, key, value as string[], order);
  } else if (kind === 'map') {
    setEntries(state, ref, key, value as [string, string][], order);
  } else if (kind === 'number') {
    const text = value as string;
    // Text that is no number yet stays text, for the hub to refuse.
    setScalar(state, ref, key, plainNumber.test(text) ? { number: text } : text, order);
  } else {
    setScalar(state, ref, key, value as string | boolean, order);
  }
}

/** Sets a top-level field, or a step's id or description. Empty removes it. */
export function setKey(source: string, ref: StepRef, key: string, value: string): string {
  return edit(source, (state) => {
    applyField(state, ref, key, value);
  });
}

/** Sets a field of a step. Empty removes it. */
export function setField(
  source: string,
  ref: { section: Section; index: number },
  field: FieldSpec,
  value: FieldValue | undefined,
): string {
  return edit(source, (state) => {
    applyField(state, ref, field, value);
  });
}

function sectionSeq(state: EditState, section: Section): { seq: YAMLSeq; steps: Raw[] } {
  const seq = state.root.get(section, true);
  if (!isSeq(seq)) {
    throw new Error(`${section} is not a list`);
  }
  return { seq, steps: state.tree[section] as Raw[] };
}

/** Adds a step of this type at the end of a section. */
export function addStep(source: string, section: Section, type: string): string {
  return edit(source, (state) => {
    const { root, tree, splices } = state;
    const step = Object.create(null) as RawMap;
    step.type = leafOf(type);
    const pad = indentsSequences(source) ? indentOf(source) : 0;
    const line = `${' '.repeat(pad)}- type: ${plainText(type, false)}`;
    const pair = findPair(root, section);
    if (!pair) {
      tree[section] = [step];
      insertPair(state, root, section, `${section}:\n${line}`, rootKeys);
      return;
    }
    const seq = pair.value;
    if (isScalar(seq) && seq.value === null) {
      tree[section] = [step];
      const end = nextLine(source, rangeOf(pair.key)[1]);
      insertLines(state, end, line);
      return;
    }
    if (!isSeq(seq)) {
      throw new Error(`${section} is not a list`);
    }
    (tree[section] as Raw[]).push(step);
    if (!seq.flow) {
      const last: unknown = seq.items[seq.items.length - 1];
      const column = columnOf(source, dashOf(source, last));
      insertLines(state, endOfLines(source, last), `${' '.repeat(column)}- type: ${plainText(type, false)}`);
    } else if (seq.items.length > 0) {
      const parts = seq.items.map((item) => flowItemText(source, item));
      writeFlow(state, seq, [...parts, `{type: ${plainText(type, true)}}`]);
    } else {
      const [from, to] = rangeOf(seq);
      const start = source.slice(0, from).trimEnd().length;
      splices.push({ from: start, to, text: `\n${line}` });
    }
  });
}

export function removeStep(source: string, section: Section, index: number): string {
  return edit(source, (state) => {
    const { seq, steps } = sectionSeq(state, section);
    const item: unknown = seq.items[index];
    steps.splice(index, 1);
    if (seq.flow) {
      const parts = seq.items.filter((_, i) => i !== index).map((other) => flowItemText(source, other));
      writeFlow(state, seq, parts);
      return;
    }
    const from = lineStart(source, dashOf(source, item));
    state.splices.push({ from, to: endOfLines(source, item), text: '' });
    if (seq.items.length === 1) {
      // No items would read as null, which the hub refuses.
      const pair = findPair(state.root, section);
      const colon = source.indexOf(':', rangeOf(pair?.key)[1]) + 1;
      state.splices.push({ from: colon, to: colon, text: ' []' });
    }
  });
}

/** A block list item's lines, with the comment lines directly above it. */
function itemLines(source: string, item: unknown): { from: number; to: number } {
  const dash = dashOf(source, item);
  const column = columnOf(source, dash);
  let from = lineStart(source, dash);
  while (from > 0) {
    const above = lineStart(source, from - 1);
    const line = source.slice(above, from - 1);
    if (!line.trimStart().startsWith('#') || columnOf(source, above + line.indexOf('#')) !== column) {
      break;
    }
    from = above;
  }
  return { from, to: endOfLines(source, item) };
}

/** Moves a step up (-1) or down (+1) within its section. */
export function moveStep(source: string, section: Section, index: number, delta: -1 | 1): string {
  return edit(source, (state) => {
    const { seq, steps } = sectionSeq(state, section);
    const other = index + delta;
    if (other < 0 || other >= seq.items.length) {
      return;
    }
    const first = Math.min(index, other);
    const [a, b] = [steps[first] as Raw, steps[first + 1] as Raw];
    steps[first] = b;
    steps[first + 1] = a;
    if (seq.flow) {
      const parts = seq.items.map((item) => flowItemText(source, item));
      const moved = parts[first] ?? '';
      parts[first] = parts[first + 1] ?? '';
      parts[first + 1] = moved;
      writeFlow(state, seq, parts);
      return;
    }
    const upper = itemLines(source, seq.items[first]);
    const lower = itemLines(source, seq.items[first + 1]);
    let top = source.slice(upper.from, upper.to);
    let bottom = source.slice(lower.from, lower.to);
    if (!bottom.endsWith('\n')) {
      // The last line of a file without a final newline changes places.
      bottom += '\n';
      top = top.replace(/\n$/, '');
    }
    state.splices.push({ from: upper.from, to: lower.to, text: bottom + source.slice(upper.to, lower.from) + top });
  });
}

/**
 * Writes a file back through the editor without changing anything: every value
 * the form shows is set again. It is what saving an untouched form would do,
 * and what the round-trip test exercises.
 */
export function writeBack(source: string): string {
  const read = readAutomation(source);
  if (!read.ok) {
    throw new Error(read.problems[0]?.message ?? 'the file does not parse');
  }
  const { model } = read;
  let out = source;
  for (const key of ['id', 'description', 'mode'] as const) {
    if (model[key] !== '') {
      out = setKey(out, null, key, model[key]);
    }
  }
  for (const section of sections) {
    for (const block of model.blocks[section]) {
      if (block.kind !== 'step') {
        continue;
      }
      const ref = { section, index: block.index };
      for (const key of ['id', 'description'] as const) {
        if (block[key] !== '') {
          out = setKey(out, ref, key, block[key]);
        }
      }
      for (const field of block.spec.fields) {
        const value = block.values[field.key];
        if (value !== undefined) {
          out = setField(out, ref, field, value);
        }
      }
    }
  }
  return out;
}

/** A new automation's starting point. */
export function newAutomationYaml(id: string): string {
  return `id: ${id}
triggers:
  - type: manual
actions:
  - type: log
    message: hello from Hearth
`;
}
