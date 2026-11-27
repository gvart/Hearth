// The app's map: four numbered sheets, each a few pages, and the command bar's search over them.
// Kept apart from the components so node --test can check it (web/test/nav.test.mjs).

export type Page =
  | 'devices'
  | 'network'
  | 'platforms'
  | 'runbooks'
  | 'automations'
  | 'notifications'
  | 'panels'
  | 'audit'
  | 'approvals'
  | 'cluster'
  | 'settings'
  | 'access'
  | 'policy'
  | 'backup'
  | 'integrations'
  | 'deviceplugins';

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
    { id: 'platforms', label: 'Platforms', hash: '#/platforms' },
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
      { id: 'settings', label: 'General', hash: '#/settings' },
      { id: 'access', label: 'Access', hash: '#/settings/access' },
      { id: 'policy', label: 'Policy', hash: '#/settings/policy' },
      { id: 'notifications', label: 'Notifications', hash: '#/notifications' },
      { id: 'backup', label: 'Backup', hash: '#/settings/backup' },
      { id: 'integrations', label: 'Integrations', hash: '#/settings/integrations' },
      { id: 'deviceplugins', label: 'Device plugins', hash: '#/settings/device-plugins' },
      { id: 'cluster', label: 'Cluster', hash: '#/cluster' },
    ],
  },
];

const byLength = sheets.flatMap((s) => s.pages).sort((a, b) => b.hash.length - a.hash.length);

/** Where Kubernetes and Proxmox lived before Platforms held them: old links still land there. */
const moved = ['#/kubernetes', '#/proxmox'];

/** The page a URL hash names. Anything unknown, and a device link, is Devices. */
export function pageOf(hash: string): Page {
  if (moved.some((m) => hash.startsWith(m))) {
    return 'platforms';
  }
  // The longest link wins: #/settings/access is Access, not General at #/settings.
  return byLength.find((p) => p.hash !== '#/' && hash.startsWith(p.hash))?.id ?? 'devices';
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

/** Links that open a page with something already under way. */
export const addDeviceHash = '#/add-device';
export const connectPlatformHash = '#/platforms/connect';
const planPrefix = '#/runbooks/plan/';

/** The link that opens the Runbooks page at one runbook, its plan shown and Start run a press away. */
export function planHash(id: string): string {
  return planPrefix + encodeURIComponent(id);
}

/** The runbook a hash asks the plan of, if it is such a link. */
export function planOfHash(hash: string): string | undefined {
  if (!hash.startsWith(planPrefix) || hash.length === planPrefix.length) {
    return undefined;
  }
  try {
    return decodeURIComponent(hash.slice(planPrefix.length));
  } catch {
    return undefined;
  }
}

export type CommandKind = 'Go to' | 'Device' | 'Platform' | 'Runbook' | 'Run';

/**
 * Something the command bar can do: open a page, a device, a platform or a
 * runbook's plan, or run something of the UI itself. A Run command never acts
 * on a device: what changes the lab still asks on its own page.
 */
export interface Command {
  kind: CommandKind;
  label: string;
  /** A second line: the sheet of a page, the state of a device. */
  hint: string;
  /** Where the command leads. */
  hash?: string;
  /** The theme the command switches to, instead of leading anywhere. */
  theme?: 'blueprint' | 'paper';
}

export interface CommandDevice {
  id: string;
  name: string;
  hostname: string;
  status: string;
}

/** What the command bar searches besides the pages. */
export interface CommandSources {
  devices: CommandDevice[];
  /** Connected clusters and servers, each with its link. */
  platforms?: { name: string; kind: string; hash: string }[];
  runbooks?: { id: string; description?: string }[];
  /** Whether this hub is a cluster member: the Cluster page is offered on one only. */
  cluster: boolean;
  /** The theme in use: the other one is offered. */
  theme?: 'blueprint' | 'paper';
  /** Whether runbooks can be written in the UI (the hub keeps its configuration in the store). */
  editable?: boolean;
}

const maxResults = 8;

/**
 * What a query finds, in this order: pages, devices, platforms, runbooks, then
 * what the UI can run. Every word of the query must appear in the name; an
 * empty query finds nothing.
 */
export function findCommands(query: string, src: CommandSources): Command[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) {
    return [];
  }
  const matches = (text: string) => words.every((w) => text.toLowerCase().includes(w));
  const out: Command[] = [];
  for (const sheet of sheets) {
    for (const p of sheet.pages) {
      if ((p.id !== 'cluster' || src.cluster) && matches(`${p.label} ${sheet.label}`)) {
        // "General" alone says nothing in a list of results: it is the Settings sheet's own page.
        const label = p.id === 'settings' ? 'Settings' : p.label;
        out.push({ kind: 'Go to', label, hint: `${sheet.no} ${sheet.label}`, hash: p.hash });
      }
    }
  }
  for (const d of src.devices) {
    if (matches(`${d.name} ${d.hostname}`)) {
      out.push({ kind: 'Device', label: d.name || d.hostname || d.id, hint: d.status, hash: deviceHash(d.id) });
    }
  }
  for (const p of src.platforms ?? []) {
    if (matches(`${p.name} ${p.kind}`)) {
      out.push({ kind: 'Platform', label: p.name, hint: p.kind, hash: p.hash });
    }
  }
  for (const r of src.runbooks ?? []) {
    if (matches(`${r.id} runbook plan`)) {
      out.push({ kind: 'Runbook', label: r.id, hint: r.description ?? 'Plan and start', hash: planHash(r.id) });
    }
  }
  const runs: Command[] = [
    { kind: 'Run', label: 'Add a device', hint: 'Enrollment command', hash: addDeviceHash },
    { kind: 'Run', label: 'Connect a platform', hint: 'Kubernetes, Proxmox, ESPHome, OpenWrt, OPNsense or UniFi', hash: connectPlatformHash },
    { kind: 'Run', label: 'New automation', hint: 'Editor', hash: '#/automations/new' },
  ];
  if (src.editable) {
    runs.push({ kind: 'Run', label: 'New runbook', hint: 'Workbench', hash: '#/runbooks/new' });
  }
  if (src.theme) {
    const other = src.theme === 'paper' ? 'blueprint' : 'paper';
    runs.push({
      kind: 'Run',
      label: `Switch theme to ${other === 'paper' ? 'Paper' : 'Blueprint'}`,
      hint: 'This browser',
      theme: other,
    });
  }
  out.push(...runs.filter((r) => matches(r.label)));
  return out.slice(0, maxResults);
}
