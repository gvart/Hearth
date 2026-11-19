// Guest and kiosk panels: the routing and the panel builder's logic, kept
// apart from the components so node --test can check it
// (web/test/panels.test.mjs). See docs/panels.md.

import type { Device, Panel, PanelInput } from './api/client.ts';

/** The path of a share link; the token follows. */
export const panelRoute = '/p/';

/** The token of a share link path (/p/<token>), or null for any other path. */
export function panelToken(pathname: string): string | null {
  if (!pathname.startsWith(panelRoute)) {
    return null;
  }
  const token = pathname.slice(panelRoute.length);
  return token === '' || token.includes('/') ? null : decodeURIComponent(token);
}

/** Whether a share link's query asks for kiosk mode: ?kiosk=1. */
export function isKiosk(search: string): boolean {
  const v = new URLSearchParams(search).get('kiosk');
  return v === '1' || v === 'true';
}

/** The full URL of a share link, in kiosk mode or not. */
export function shareURL(origin: string, path: string, kiosk: boolean): string {
  return origin + path + (kiosk ? '?kiosk=1' : '');
}

/**
 * The services a panel may offer to restart on a device: those its agent
 * allows (--allow-restart). The hub checks the ceiling again on every action.
 */
export function restartServices(d: Device | undefined): string[] {
  return [...(d?.facts.ceiling?.restart ?? [])].sort();
}

/** How long a new share link lasts. */
export const linkExpiries: readonly { label: string; value: string }[] = [
  { label: 'Never expires', value: '' },
  { label: '24 hours', value: '24h' },
  { label: '7 days', value: '168h' },
  { label: '30 days', value: '720h' },
];

/** A saved panel as a save request, keeping its widget IDs. */
export function toInput(p: Panel): PanelInput {
  return {
    name: p.name,
    widgets: p.widgets.map((w) => ({
      id: w.id,
      kind: w.kind,
      entity: w.entity,
      actions: w.actions.map((a) => (a.service ? { action: a.action, service: a.service } : { action: a.action })),
    })),
  };
}

/** The panel with a widget for device added, unless it has one already. */
export function addDevice(p: PanelInput, device: string): PanelInput {
  if (device === '' || p.widgets.some((w) => w.entity === device)) {
    return p;
  }
  return { ...p, widgets: [...p.widgets, { kind: 'device', entity: device, actions: [] }] };
}

/** The panel with the restart of service on widget i allowed or not. */
export function toggleRestart(p: PanelInput, i: number, service: string, on: boolean): PanelInput {
  return {
    ...p,
    widgets: p.widgets.map((w, j) => {
      if (j !== i) {
        return w;
      }
      const others = w.actions.filter((a) => !(a.action === 'device.restart' && a.service === service));
      return { ...w, actions: on ? [...others, { action: 'device.restart', service }] : others };
    }),
  };
}

/** The panel with widget i moved by delta (-1 up, 1 down), or removed with delta 0. */
export function moveWidget(p: PanelInput, i: number, delta: -1 | 0 | 1): PanelInput {
  const widgets = [...p.widgets];
  const [w] = widgets.splice(i, 1);
  if (w && delta !== 0) {
    widgets.splice(Math.max(0, Math.min(widgets.length, i + delta)), 0, w);
  }
  return { ...p, widgets };
}
