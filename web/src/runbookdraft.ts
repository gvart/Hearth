// A runbook drafted from a recorded terminal session, on its way to the
// runbook editor: kept in this tab's sessionStorage only, until the editor
// has read it. Apart from the components so node --test can check it
// (web/test/runbookdraft.test.mjs).

/** What the editor shows of a draft: the file and who wrote it. Never the transcript. */
export interface StashedRunbookDraft {
  yaml: string;
  model: string;
  attempts: number;
  valid: boolean;
  problems: { line?: number; message: string }[];
}

const key = 'hearth.runbook.draft';

/** Minimal Storage, so tests can pass their own. */
interface DraftStorage {
  getItem(k: string): string | null;
  setItem(k: string, v: string): void;
  removeItem(k: string): void;
}

function store(s?: DraftStorage): DraftStorage | null {
  if (s) {
    return s;
  }
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

/** Keeps a draft for the editor this tab opens next. */
export function stashRunbookDraft(d: StashedRunbookDraft, s?: DraftStorage): boolean {
  const st = store(s);
  if (!st) {
    return false;
  }
  try {
    const { yaml, model, attempts, valid, problems } = d;
    st.setItem(key, JSON.stringify({ yaml, model, attempts, valid, problems }));
    return true;
  } catch {
    return false;
  }
}

/** The draft stashed for the editor, if any. It stays until clearRunbookDraft. */
export function readRunbookDraft(s?: DraftStorage): StashedRunbookDraft | null {
  const st = store(s);
  if (!st) {
    return null;
  }
  try {
    const raw = st.getItem(key);
    if (!raw) {
      return null;
    }
    const d = JSON.parse(raw) as Partial<StashedRunbookDraft>;
    if (typeof d.yaml !== 'string' || d.yaml === '') {
      return null;
    }
    return {
      yaml: d.yaml,
      model: typeof d.model === 'string' ? d.model : '',
      attempts: typeof d.attempts === 'number' ? d.attempts : 1,
      valid: d.valid === true,
      problems: Array.isArray(d.problems) ? d.problems : [],
    };
  } catch {
    return null;
  }
}

/** Forgets the stashed draft, once the editor has it. */
export function clearRunbookDraft(s?: DraftStorage): void {
  try {
    store(s)?.removeItem(key);
  } catch {
    // Nothing to forget.
  }
}

/** What the runbook editor says about a draft it opened. */
export function runbookDraftNotice(d: { model: string; attempts: number; valid: boolean; problems: unknown[] }): string {
  const by = `Drafted by ${d.model} from a recorded terminal session${d.attempts > 1 ? ` (${String(d.attempts)} tries)` : ''}. Nothing is saved yet.`;
  if (d.valid) {
    return `${by} Review every step and its plan below, then Save.`;
  }
  const n = d.problems.length;
  return `${by} The hub does not accept it yet (${String(n)} problem${n === 1 ? '' : 's'}): fix ${n === 1 ? 'it' : 'them'} below.`;
}
