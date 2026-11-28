// What the AI settings form and the Explain card decide, apart from the
// components so node --test can check it (web/test/ai.test.mjs).

export type AIProvider = 'openai' | 'anthropic';

/** The settings form as typed: an empty field takes the provider's default. */
export interface AIForm {
  provider: AIProvider | '';
  base_url: string;
  model: string;
  /** Write-only: empty keeps the stored key for the same provider and address. */
  api_key: string;
  clear_api_key: boolean;
}

/** What a provider asks for, and what it fills in when a field is left empty. */
export const providers: Record<AIProvider, { label: string; baseURL: string; model: string; keyNeeded: boolean; hint: string }> = {
  openai: {
    label: 'OpenAI-compatible (Ollama, LM Studio, vLLM, OpenAI)',
    baseURL: 'http://127.0.0.1:11434/v1',
    model: 'llama3.2',
    keyNeeded: false,
    hint: 'The address ends in /v1. A local server needs no key; with Ollama nothing leaves your lab.',
  },
  anthropic: {
    label: 'Anthropic',
    baseURL: 'https://api.anthropic.com',
    model: 'claude-opus-5-5',
    keyNeeded: true,
    hint: 'Leave the address and model empty for Anthropic’s API and its default model. The evidence leaves your lab, redacted.',
  },
};

/** The body of PUT /ai/config for a form. Empty fields are sent as they are: the hub fills in defaults. */
export function aiEditBody(form: AIForm, revision: string) {
  if (form.provider === '') {
    return { provider: '', revision };
  }
  return {
    provider: form.provider,
    base_url: form.base_url.trim(),
    model: form.model.trim(),
    api_key: form.api_key.trim(),
    clear_api_key: form.clear_api_key && form.api_key.trim() === '',
    revision,
  };
}

/** Whether the form can be saved: a provider that needs a key has one, stored or typed. */
export function aiFormReady(form: AIForm, storedKey: boolean, sameTarget: boolean): boolean {
  if (form.provider === '') {
    return true;
  }
  const p = providers[form.provider];
  if (form.provider === 'openai' && (form.base_url.trim() === '' || form.model.trim() === '')) {
    return false;
  }
  const hasKey = form.api_key.trim() !== '' || (storedKey && sameTarget && !form.clear_api_key);
  return !p.keyNeeded || hasKey;
}

/** The log sources typed into the Explain card: manager:name, one per line or comma, at most three. */
export function parseLogSources(text: string): { sources: string[]; error: string } {
  const sources = [...new Set(text.split(/[\n,]/).map((s) => s.trim()).filter((s) => s !== ''))];
  for (const s of sources) {
    const i = s.indexOf(':');
    if (i <= 0 || i === s.length - 1) {
      return { sources, error: `"${s}" is not manager:name, such as systemd:nginx.service` };
    }
  }
  if (sources.length > 3) {
    return { sources, error: 'At most three logs.' };
  }
  return { sources, error: '' };
}

/** The browser remembers that its user saw a preview once: the first explanation shows one before sending. */
export const previewSeenKey = 'hearth.ai.previewSeen';

/** What the editor says about a draft it just opened: who wrote it, and what is left to do. */
export function draftNotice(d: { model: string; attempts: number; valid: boolean; problems: unknown[] }): string {
  const by = `Drafted by ${d.model}${d.attempts > 1 ? ` (${String(d.attempts)} tries)` : ''}. Nothing is saved yet.`;
  if (d.valid) {
    return `${by} Review every step, check the dry run below, then Save.`;
  }
  const n = d.problems.length;
  return `${by} The hub does not accept it yet (${String(n)} problem${n === 1 ? '' : 's'}): fix ${n === 1 ? 'it' : 'them'} in the YAML view, or describe it again.`;
}
