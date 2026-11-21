// The kinds of host network discovery tells apart (docs/discovery.md, "Kinds"):
// a label and a mark for each. Kept apart from the components so node --test
// can check it (web/test/hostkinds.test.mjs).

import type { NetworkHost, NetworkHostKind } from './api/client.ts';

export interface HostKindInfo {
  label: string;
  /** The mark: path data on a 16 × 16 grid, drawn as lines, like the network map's glyphs. */
  path: string;
}

export const hostKinds: Record<NetworkHostKind, HostKindInfo> = {
  router: { label: 'Router', path: 'M2 9h12v5H2z M5 9V3 M11 9V3 M5 11.5h2' },
  printer: { label: 'Printer', path: 'M4 6V2h8v4 M2 6h12v6H2z M4 10h8v4H4z' },
  media: { label: 'Media', path: 'M1 2h14v9H1z M5 14h6 M8 11v3' },
  phone: { label: 'Phone', path: 'M5 1h6v14H5z M7 12.5h2' },
  computer: { label: 'Computer', path: 'M3 3h10v7H3z M1 13h14' },
  nas: { label: 'NAS', path: 'M2 2h12v5H2z M2 9h12v5H2z M4 4.5h2 M4 11.5h2' },
  iot: { label: 'Smart device', path: 'M5 5h6v6H5z M7 2v3 M9 2v3 M7 11v3 M9 11v3 M2 7h3 M2 9h3 M11 7h3 M11 9h3' },
  unknown: { label: 'Unknown', path: 'M5 5h6v6H5z' },
};

/** The hover text of a host's kind: what it announces, and whether it can run an agent. */
export function hostKindTitle(h: Pick<NetworkHost, 'kind' | 'services' | 'agent_capable'>): string {
  const parts = [hostKinds[h.kind].label];
  if (h.services.length > 0) {
    parts.push(`Announces ${h.services.join(', ')}`);
  }
  if (h.agent_capable) {
    parts.push('Looks able to run a Hearth agent');
  }
  return parts.join('. ');
}
