// The app's map: four numbered sheets, each a few pages, and the command bar's search over them.
// Kept apart from the components so node --test can check it (web/test/nav.test.mjs).

export type Page =
  | 'devices'
  | 'network'
  | 'kubernetes'
  | 'proxmox'
  | 'runbooks'
  | 'automations'
  | 'notifications'
  | 'panels'
  | 'audit'
  | 'approvals'
  | 'cluster'
  | 'settings';

export type SheetId = 'lab' | 'automate' | 'activity' | 'settings';

export interface NavPage {
  id: Page;
  label: string;
  hash: string;
}

/** A section of the app, numbered like the sheets of a drawing set. */
export interface Sheet {
  id: SheetId;
  no: string;
  label: string;
  pages: NavPage[];
}

const lab: Sheet = {
  id: 'lab',
  no: '01',
  label: 'Lab',
  pages: [
    { id: 'devices', label: 'Devices', hash: '#/' },
    { id: 'network', label: 'Network', hash: '#/network' },
    { id: 'kubernetes', label: 'Kubernetes', hash: '#/kubernetes' },
    { id: 'proxmox', label: 'Proxmox', hash: '#/proxmox' },
  ],
};

export const sheets: Sheet[] = [
  lab,
  {
    id: 'automate',
    no: '02',
    label: 'Automate',
    pages: [
      { id: 'automations', label: 'Automations', hash: '#/automations' },
      { id: 'runbooks', label: 'Runbooks', hash: '#/runbooks' },
      { id: 'panels', label: 'Panels', hash: '#/panels' },
    ],
  },
  {
    id: 'activity',
    no: '03',
    label: 'Activity',
    pages: [
      { id: 'approvals', label: 'Approvals', hash: '#/approvals' },
      { id: 'audit', label: 'Audit', hash: '#/audit' },
    ],
  },
  {
    id: 'settings',
    no: '04',
    label: 'Settings',
    pages: [
      { id: 'settings', label: 'Settings', hash: '#/settings' },
      { id: 'notifications', label: 'Notifications', hash: '#/notifications' },
      { id: 'cluster', label: 'Cluster', hash: '#/cluster' },
    ],
  },
];

const allPages = sheets.flatMap((s) => s.pages);

/** The page a URL hash names. Anything unknown, and a device link, is Devices. */
export function pageOf(hash: string): Page {
  return allPages.find((p) => p.hash !== '#/' && hash.startsWith(p.hash))?.id ?? 'devices';
}

/** The sheet a page belongs to. */
export function sheetOf(page: Page): Sheet {
  return sheets.find((s) => s.pages.some((p) => p.id === page)) ?? lab;
}

/** Where a sheet's tab leads: its first page. */
export function sheetHash(sheet: Sheet): string {
  return sheet.pages[0]?.hash ?? '#/';
}

/**
 * A sheet's pages as the navigation shows them. The Cluster page is offered on a
 * cluster member only, and stays listed while it is open.
 */
export function pagesOf(sheet: Sheet, opts: { cluster: boolean; current: Page }): NavPage[] {
  return sheet.pages.filter((p) => p.id !== 'cluster' || opts.cluster || opts.current === 'cluster');
}

const devicePrefix = '#/devices/';

/** The link that opens a device on the Devices page. */
export function deviceHash(id: string): string {
  return devicePrefix + encodeURIComponent(id);
}

/** The device a hash opens, if it is a device link. */
export function deviceOfHash(hash: string): string | undefined {
  if (!hash.startsWith(devicePrefix) || hash.length === devicePrefix.length) {
    return undefined;
  }
  try {
    return decodeURIComponent(hash.slice(devicePrefix.length));
  } catch {
    return undefined;
  }
}

/** Something the command bar can open. */
export interface Command {
  kind: 'Go to' | 'Device';
  label: string;
  /** A second line: the sheet of a page, the state of a device. */
  hint: string;
  hash: string;
}

export interface CommandDevice {
  id: string;
  name: string;
  hostname: string;
  status: string;
}

const maxResults = 8;

/**
 * What a query finds: pages first, then devices. Every word of the query must
 * appear in the page's or device's name; an empty query finds nothing.
 */
export function findCommands(query: string, devices: CommandDevice[], opts: { cluster: boolean }): Command[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) {
    return [];
  }
  const matches = (text: string) => words.every((w) => text.toLowerCase().includes(w));
  const out: Command[] = [];
  for (const sheet of sheets) {
    for (const p of sheet.pages) {
      if ((p.id !== 'cluster' || opts.cluster) && matches(`${p.label} ${sheet.label}`)) {
        out.push({ kind: 'Go to', label: p.label, hint: `${sheet.no} ${sheet.label}`, hash: p.hash });
      }
    }
  }
  for (const d of devices) {
    if (matches(`${d.name} ${d.hostname}`)) {
      out.push({ kind: 'Device', label: d.name || d.hostname || d.id, hint: d.status, hash: deviceHash(d.id) });
    }
  }
  return out.slice(0, maxResults);
}
