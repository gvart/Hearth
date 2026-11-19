// The visual editor's view of an automation file. The YAML text is the only
// state: the model is read from it, and every edit changes the parsed document
// in place and writes it back, so comments, key order and anything the editor
// cannot show stay as they were. No React here: test/ runs this under Node.

import {
  Document,
  isMap,
  isScalar,
  isSeq,
  Pair,
  parseDocument,
  Scalar,
  visit,
  YAMLMap,
  YAMLSeq,
} from 'yaml';
import type { Node as YamlNode } from 'yaml';
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

export type ParseResult = { ok: true; model: AutomationModel } | { ok: false; problems: YamlProblem[] };

const rootKeys = ['id', 'description', 'mode', ...sections];

function lineOf(source: string, offset: number): number {
  return source.slice(0, offset).split('\n').length;
}

function parse(source: string): Document.Parsed {
  return parseDocument(source, { prettyErrors: false });
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

function stringOf(node: unknown): string | undefined {
  return isScalar(node) && typeof node.value === 'string' ? node.value : undefined;
}

/** The form's value of a node, or undefined if the form cannot show it. */
function readField(spec: FieldSpec, node: unknown): FieldValue | undefined {
  switch (spec.kind) {
    case 'number':
      return isScalar(node) && typeof node.value === 'number' && Number.isFinite(node.value)
        ? (node.source ?? String(node.value))
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
      return items.every((s): s is string => s !== undefined && s !== '' && !s.includes('\n')) ? items : undefined;
    }
    case 'map': {
      if (!isMap(node)) {
        return undefined;
      }
      const entries: [string, string][] = [];
      for (const pair of node.items) {
        const key = stringOf(pair.key);
        const value = stringOf(pair.value);
        if (key === undefined || value === undefined || key.includes(':') || `${key}${value}`.includes('\n')) {
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

function targetMap(doc: Document.Parsed, ref: StepRef): YAMLMap {
  const root = doc.contents;
  if (!isMap(root)) {
    throw new Error('the file is not a mapping');
  }
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

/** Adds a pair after the nearest key that comes before it in order. */
function insertOrdered(map: YAMLMap, pair: Pair, order: string[]): void {
  const at = order.indexOf(stringOf(pair.key) ?? '');
  let index = -1;
  map.items.forEach((p, i) => {
    const pos = order.indexOf(stringOf(p.key) ?? '');
    if (pos !== -1 && pos < at) {
      index = i;
    }
  });
  const hasOrdered = index !== -1 || map.items.some((p) => order.indexOf(stringOf(p.key) ?? '') > at);
  map.items.splice(hasOrdered ? index + 1 : map.items.length, 0, pair);
}

function setScalar(doc: Document.Parsed, map: YAMLMap, key: string, value: string | number | boolean, order: string[]) {
  const existing = map.get(key, true);
  if (isScalar(existing)) {
    if (typeof value === 'string' && typeof existing.value === 'string') {
      // Keeps its quoting and comments.
      existing.value = value;
      return;
    }
    if (existing.value === value) {
      return;
    }
    const next = new Scalar(value);
    next.comment = existing.comment;
    next.commentBefore = existing.commentBefore;
    next.spaceBefore = existing.spaceBefore;
    map.set(key, next);
    return;
  }
  map.delete(key);
  insertOrdered(map, doc.createPair(key, value), order);
}

function setList(doc: Document.Parsed, map: YAMLMap, key: string, items: string[], order: string[]) {
  const seq = map.get(key, true);
  if (!isSeq(seq)) {
    map.delete(key);
    const created = doc.createNode(items) as YAMLSeq;
    created.flow = true;
    insertOrdered(map, new Pair(new Scalar(key), created), order);
    return;
  }
  items.forEach((item, i) => {
    const node = seq.items[i];
    if (isScalar(node)) {
      node.value = item;
    } else {
      seq.items[i] = doc.createNode(item);
    }
  });
  seq.items.length = items.length;
}

function setEntries(doc: Document.Parsed, map: YAMLMap, key: string, entries: [string, string][], order: string[]) {
  const target = map.get(key, true);
  if (!isMap(target)) {
    map.delete(key);
    insertOrdered(map, doc.createPair(key, Object.fromEntries(entries)), order);
    return;
  }
  target.items = entries.map(([k, v]) => {
    const pair = target.items.find((p) => stringOf(p.key) === k);
    if (!pair) {
      return doc.createPair(k, v);
    }
    if (isScalar(pair.value)) {
      pair.value.value = v;
    }
    return pair;
  });
}

function isEmpty(value: FieldValue | undefined): boolean {
  return value === undefined || value === '' || (Array.isArray(value) && value.length === 0);
}

function applyField(doc: Document.Parsed, ref: StepRef, field: FieldSpec | string, value: FieldValue | undefined) {
  const map = targetMap(doc, ref);
  const key = typeof field === 'string' ? field : field.key;
  const kind = typeof field === 'string' ? 'text' : field.kind;
  let order = rootKeys;
  if (ref !== null) {
    const spec = stepSpecs[ref.section][stringOf(map.get('type', true)) ?? ''];
    order = ['id', 'type', 'description', ...(spec?.fields.map((f) => f.key) ?? [])];
  }
  if (isEmpty(value)) {
    map.delete(key);
  } else if (kind === 'list') {
    setList(doc, map, key, value as string[], order);
  } else if (kind === 'map') {
    setEntries(doc, map, key, value as [string, string][], order);
  } else if (kind === 'number') {
    const text = value as string;
    const n = Number(text);
    // Text that is no number yet stays text, for the hub to refuse.
    setScalar(doc, map, key, text.trim() !== '' && Number.isFinite(n) ? n : text, order);
  } else {
    setScalar(doc, map, key, value as string | boolean, order);
  }
}

function indentOf(source: string): number {
  const m = /^( +)\S/m.exec(source);
  return m?.[1] ? Math.min(m[1].length, 8) : 2;
}

/** Whether a list under a key is indented, as `triggers:\n  - x`. */
function indentsSequences(source: string): boolean {
  return !/^[\w-]+:[^\n]*\n(?:\s*#[^\n]*\n)*- /m.test(source);
}

function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** Puts back the spacing of every line the write did not really change. */
function restoreSpacing(before: string, after: string): string {
  const squeeze = (line: string) => `${/^ */.exec(line)?.[0] ?? ''}${line.replace(/\s+/g, '')}`;
  const originals = new Map<string, string[]>();
  for (const line of before.split('\n')) {
    const key = squeeze(line);
    originals.set(key, [...(originals.get(key) ?? []), line]);
  }
  const take = (key: string) => originals.get(key)?.shift();

  const lines = after.split('\n');
  const out: string[] = [];
  const changed: number[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    const next = lines[i + 1];
    // The writer moves the comment of `key:  # comment` above the key's list.
    const joined = next?.trimStart().startsWith('#') ? take(squeeze(`${line} ${next}`)) : undefined;
    if (joined !== undefined) {
      out.push(joined);
      i++;
      continue;
    }
    const same = take(squeeze(line));
    if (same === undefined) {
      changed.push(out.length);
    }
    out.push(same ?? line);
  }

  // A changed value keeps its comment in the column it was in.
  const unused = [...originals.values()].flat();
  for (const i of changed) {
    const m = /^(\s*(?:- )?[^\s:#]+:.*?\S)\s+(#.*)$/.exec(out[i] ?? '');
    const key = m?.[1] ? /^\s*(?:- )?[^\s:#]+:/.exec(m[1])?.[0] : undefined;
    if (!m?.[1] || !m[2] || key === undefined) {
      continue;
    }
    const comment = m[2];
    const was = unused.find((line) => line.startsWith(key) && line.endsWith(comment));
    if (was !== undefined) {
      const column = was.length - comment.length;
      out[i] = `${m[1].length < column ? m[1].padEnd(column) : `${m[1]} `}${comment}`;
    }
  }
  return out.join('\n');
}

/** Writes the document, keeping as much of the original text as it can. */
function render(doc: Document.Parsed, before: string): string {
  const written = doc.toString({ lineWidth: 0, indent: indentOf(before), indentSeq: indentsSequences(before) });
  const want: unknown = doc.toJS();
  if (!sameValue(parse(written).toJS(), want)) {
    throw new Error('the edit cannot be written as YAML without changing the file’s meaning');
  }
  const restored = restoreSpacing(before, written);
  const out = sameValue(parse(restored).toJS(), want) ? restored : written;
  return before.endsWith('\n') ? out : out.replace(/\n$/, '');
}

function edit(source: string, change: (doc: Document.Parsed) => void): string {
  const doc = parse(source);
  if (doc.errors.length > 0) {
    throw new Error('the file does not parse');
  }
  change(doc);
  return render(doc, source);
}

/** Sets a top-level field, or a step's id or description. Empty removes it. */
export function setKey(source: string, ref: StepRef, key: string, value: string): string {
  return edit(source, (doc) => {
    applyField(doc, ref, key, value);
  });
}

/** Sets a field of a step. Empty removes it. */
export function setField(
  source: string,
  ref: { section: Section; index: number },
  field: FieldSpec,
  value: FieldValue | undefined,
): string {
  return edit(source, (doc) => {
    applyField(doc, ref, field, value);
  });
}

function sectionSeq(doc: Document.Parsed, section: Section): YAMLSeq {
  const seq = targetMap(doc, null).get(section, true);
  if (!isSeq(seq)) {
    throw new Error(`${section} is not a list`);
  }
  return seq;
}

/** Adds a step of this type at the end of a section. */
export function addStep(source: string, section: Section, type: string): string {
  return edit(source, (doc) => {
    const root = targetMap(doc, null);
    let seq: unknown = root.get(section, true);
    if (seq === undefined || (isScalar(seq) && seq.value === null)) {
      root.delete(section);
      seq = new YAMLSeq(doc.schema);
      insertOrdered(root, new Pair(new Scalar(section), seq), rootKeys);
    }
    if (!isSeq(seq)) {
      throw new Error(`${section} is not a list`);
    }
    if (seq.items.length === 0) {
      seq.flow = false;
    }
    seq.items.push(doc.createNode({ type }));
  });
}

export function removeStep(source: string, section: Section, index: number): string {
  return edit(source, (doc) => {
    sectionSeq(doc, section).items.splice(index, 1);
  });
}

/** Moves a step up (-1) or down (+1) within its section. */
export function moveStep(source: string, section: Section, index: number, delta: -1 | 1): string {
  return edit(source, (doc) => {
    const items = sectionSeq(doc, section).items;
    const other = index + delta;
    if (other < 0 || other >= items.length) {
      return;
    }
    [items[index], items[other]] = [items[other], items[index]];
  });
}

/**
 * Writes a file back through the editor without changing anything: every value
 * the form shows is set again and the document written out. It is what saving
 * an untouched form would do, and what the round-trip test exercises.
 */
export function writeBack(source: string): string {
  const read = readAutomation(source);
  if (!read.ok) {
    throw new Error(read.problems[0]?.message ?? 'the file does not parse');
  }
  const { model } = read;
  return edit(source, (doc) => {
    for (const key of ['id', 'description', 'mode'] as const) {
      if (model[key] !== '') {
        applyField(doc, null, key, model[key]);
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
            applyField(doc, ref, key, block[key]);
          }
        }
        for (const field of block.spec.fields) {
          const value = block.values[field.key];
          if (value !== undefined) {
            applyField(doc, ref, field, value);
          }
        }
      }
    }
  });
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
