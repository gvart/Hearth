// What the plugin command dialogs share: the arguments a person types, and how a class shows.
// Kept apart from the components so fast refresh keeps working.

import type { PolicyClass } from './api/plugins.ts';

/** The pill of a command's policy class. */
export const classPill: Record<PolicyClass, string> = { read: 'pill-ok', safe: 'pill-ok', dangerous: 'pill-bad' };

/** The parsed arguments, or an error: they must be a JSON object, or nothing. */
export function parseArgs(text: string): { args?: Record<string, unknown>; error?: string } {
  if (text.trim() === '') {
    return {};
  }
  try {
    const v: unknown = JSON.parse(text);
    if (v === null || typeof v !== 'object' || Array.isArray(v)) {
      return { error: 'Arguments must be a JSON object, such as {"level": 3}.' };
    }
    return { args: v as Record<string, unknown> };
  } catch {
    return { error: 'Arguments are not valid JSON.' };
  }
}
