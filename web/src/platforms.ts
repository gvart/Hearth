// Platforms: the clusters and servers Hearth reads next to its own devices, on
// one page. Kept apart from the components so node --test can check it
// (web/test/platforms.test.mjs).

export type PlatformKind = 'kubernetes' | 'proxmox';

export const kindLabel: Record<PlatformKind, string> = {
  kubernetes: 'Kubernetes cluster',
  proxmox: 'Proxmox server',
};

/** How a platform reads now, whatever its kind calls it. */
export type PlatformState = 'connecting' | 'connected' | 'unreachable';

export const stateLabel: Record<PlatformState, string> = {
  connecting: 'Connecting',
  connected: 'Connected',
  unreachable: 'Unreachable',
};

/** One connected platform, as its card on the Platforms page shows it. */
export interface PlatformCard {
  kind: PlatformKind;
  id: string;
  name: string;
  /** Where Hearth reads it: the API server's URL. */
  address: string;
  state: PlatformState;
  /** What it holds, such as "3 nodes · 41 pods". */
  line: string;
  /** Why it cannot be read, when it cannot. */
  error: string;
  hash: string;
}

interface Cluster {
  id: string;
  name: string;
  server: string;
  state: 'connecting' | 'connected' | 'error';
  error: string;
  nodes: number;
  pods: number;
}

interface Server {
  id: string;
  name: string;
  url: string;
  state: 'connecting' | 'connected' | 'unavailable';
  error: string;
  nodes: number;
  guests: number;
}

/** The Platforms page. */
export const platformsHash = '#/platforms';

const prefix = `${platformsHash}/`;

/** The link that opens one platform. */
export function platformHash(kind: PlatformKind, id: string): string {
  return `${prefix}${kind}/${encodeURIComponent(id)}`;
}

/** The platform a hash opens, if it names one. */
export function platformOfHash(hash: string): { kind: PlatformKind; id: string } | undefined {
  if (!hash.startsWith(prefix)) {
    return undefined;
  }
  const [kind, id, ...rest] = hash.slice(prefix.length).split('/');
  if ((kind !== 'kubernetes' && kind !== 'proxmox') || !id || rest.length > 0) {
    return undefined;
  }
  try {
    return { kind, id: decodeURIComponent(id) };
  } catch {
    return undefined;
  }
}

function count(n: number, one: string, many = `${one}s`): string {
  return `${String(n)} ${n === 1 ? one : many}`;
}

/** Every connected platform as a card: unreachable ones first, then by name. */
export function platformCards(clusters: Cluster[], servers: Server[]): PlatformCard[] {
  const cards: PlatformCard[] = [
    ...clusters.map(
      (c): PlatformCard => ({
        kind: 'kubernetes',
        id: c.id,
        name: c.name,
        address: c.server,
        state: c.state === 'error' ? 'unreachable' : c.state,
        line: `${count(c.nodes, 'node')} · ${count(c.pods, 'pod')}`,
        error: c.error,
        hash: platformHash('kubernetes', c.id),
      }),
    ),
    ...servers.map(
      (s): PlatformCard => ({
        kind: 'proxmox',
        id: s.id,
        name: s.name,
        address: s.url,
        state: s.state === 'unavailable' ? 'unreachable' : s.state,
        line: `${count(s.nodes, 'host')} · ${count(s.guests, 'guest')}`,
        error: s.error,
        hash: platformHash('proxmox', s.id),
      }),
    ),
  ];
  const order: Record<PlatformState, number> = { unreachable: 0, connecting: 1, connected: 2 };
  return cards.sort((a, b) => order[a.state] - order[b.state] || a.name.localeCompare(b.name));
}

/** The line under the page's title. */
export function platformSummary(cards: PlatformCard[]): string {
  if (cards.length === 0) {
    return 'None connected yet';
  }
  const down = cards.filter((c) => c.state === 'unreachable').length;
  return `${String(cards.length)} connected${down > 0 ? ` · ${String(down)} unreachable` : ''}`;
}
