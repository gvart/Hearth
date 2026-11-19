// What the telemetry prompt says and when it shows. Kept apart from the
// component so node --test can check it (web/test/telemetry.test.mjs).

import type { TelemetrySetting } from './api/client.ts';

export const telemetryDocsURL = 'https://github.com/gvart/hearth/blob/main/docs/telemetry.md';

/** Everything an opted-in hub sends, once a week; docs/telemetry.md lists the same. */
export const telemetryFields: readonly string[] = [
  'a random install ID, made when you say yes',
  'the Hearth version',
  'the OS and CPU architecture of the hub',
  'how many devices, as a range: 0, 1–5, 6–20, 21–50 or 51+',
  'which kinds of integration are on (such as kubernetes or pihole), names only',
];

/**
 * What the UI shows: nothing while loading, the prompt until the admin
 * answers, and otherwise a status line with a toggle, or, with
 * HEARTH_TELEMETRY=off, a note that the hub turned it off.
 */
export type TelemetryView = 'loading' | 'ask' | 'on' | 'off' | 'env-off';

export function telemetryView(s: TelemetrySetting | undefined): TelemetryView {
  if (!s) {
    return 'loading';
  }
  if (s.disabled_by_env) {
    return 'env-off';
  }
  if (!s.answered) {
    return 'ask';
  }
  return s.enabled ? 'on' : 'off';
}
