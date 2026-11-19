import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { useApprovals, useDeviceEvents, useLogout } from '../api/hooks.ts';
import { ApprovalsPage } from './ApprovalsPage.tsx';
import { AuditPage } from './AuditPage.tsx';
import { ConfigDriftBanner } from './ConfigDriftBanner.tsx';
import { DevicesPage } from './DevicesPage.tsx';
import { KubernetesPage } from './KubernetesPage.tsx';
import { Logo } from './Logo.tsx';
import { NotificationsPage } from './NotificationsPage.tsx';
import { PanelsPage } from './PanelsPage.tsx';
import { ProxmoxPage } from './ProxmoxPage.tsx';
import { RunbooksPage } from './RunbooksPage.tsx';
import { TelemetryPrompt, TelemetryStatus } from './TelemetryPrompt.tsx';

// Loaded when opened: the editor brings a YAML parser no other page needs.
const AutomationsPage = lazy(() => import('./AutomationsPage.tsx'));

type Page =
  | 'devices'
  | 'kubernetes'
  | 'proxmox'
  | 'runbooks'
  | 'automations'
  | 'notifications'
  | 'panels'
  | 'audit'
  | 'approvals';

const pages: { id: Page; label: string; hash: string }[] = [
  { id: 'devices', label: 'Devices', hash: '#/' },
  { id: 'kubernetes', label: 'Kubernetes', hash: '#/kubernetes' },
  { id: 'proxmox', label: 'Proxmox', hash: '#/proxmox' },
  { id: 'runbooks', label: 'Runbooks', hash: '#/runbooks' },
  { id: 'automations', label: 'Automations', hash: '#/automations' },
  { id: 'panels', label: 'Panels', hash: '#/panels' },
  { id: 'notifications', label: 'Notifications', hash: '#/notifications' },
  { id: 'audit', label: 'Audit', hash: '#/audit' },
  { id: 'approvals', label: 'Approvals', hash: '#/approvals' },
];

function pageOf(hash: string): Page {
  if (hash.startsWith('#/approvals')) {
    return 'approvals';
  }
  if (hash.startsWith('#/runbooks')) {
    return 'runbooks';
  }
  if (hash.startsWith('#/panels')) {
    return 'panels';
  }
  if (hash.startsWith('#/notifications')) {
    return 'notifications';
  }
  if (hash.startsWith('#/audit')) {
    return 'audit';
  }
  if (hash.startsWith('#/proxmox')) {
    return 'proxmox';
  }
  if (hash.startsWith('#/automations')) {
    return 'automations';
  }
  return hash.startsWith('#/kubernetes') ? 'kubernetes' : 'devices';
}

/** The page chosen by the URL hash, so reloads and links keep it. */
function usePage(): Page {
  const [page, setPage] = useState(() => pageOf(window.location.hash));
  useEffect(() => {
    const onHash = () => {
      setPage(pageOf(window.location.hash));
    };
    window.addEventListener('hashchange', onHash);
    return () => {
      window.removeEventListener('hashchange', onHash);
    };
  }, []);
  return page;
}

/** The signed-in app: top bar, navigation and the live event stream. */
export function Shell() {
  useDeviceEvents();
  const logout = useLogout();
  const page = usePage();
  const waiting = useApprovals('pending').data?.length ?? 0;
  const nav = useRef<HTMLElement>(null);
  const activeLink = useRef<HTMLAnchorElement>(null);

  // On a phone the links scroll sideways: keep the current page's link in view,
  // also when the waiting badge widens it or the nav narrows, as it does when a
  // page's data arrives and brings a classic scrollbar with it.
  useEffect(() => {
    const observer = new ResizeObserver(() => {
      activeLink.current?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    });
    if (nav.current) {
      observer.observe(nav.current);
    }
    return () => {
      observer.disconnect();
    };
  }, [page, waiting]);

  return (
    <div className="app">
      <header className="topbar">
        <div className="topbar-left">
          <div className="brand">
            <Logo size={28} />
            <span>Hearth</span>
          </div>
          <nav ref={nav} className="nav" aria-label="Sections">
            {pages.map((p) => (
              <a
                key={p.id}
                ref={page === p.id ? activeLink : undefined}
                href={p.hash}
                className="nav-link"
                aria-current={page === p.id ? 'page' : undefined}
              >
                {p.label}
                {p.id === 'approvals' && waiting > 0 ? (
                  <span className="badge nav-badge" aria-label={`${String(waiting)} waiting`}>
                    {waiting}
                  </span>
                ) : null}
              </a>
            ))}
          </nav>
        </div>
        <button
          className="btn btn-ghost"
          type="button"
          onClick={() => {
            logout.mutate();
          }}
        >
          Sign out
        </button>
      </header>
      <ConfigDriftBanner />
      <TelemetryPrompt />
      {page === 'approvals' ? (
        <ApprovalsPage />
      ) : page === 'kubernetes' ? (
        <KubernetesPage />
      ) : page === 'proxmox' ? (
        <ProxmoxPage />
      ) : page === 'runbooks' ? (
        <RunbooksPage />
      ) : page === 'automations' ? (
        <Suspense fallback={<main className="content muted">Loading automations…</main>}>
          <AutomationsPage />
        </Suspense>
      ) : page === 'panels' ? (
        <PanelsPage />
      ) : page === 'notifications' ? (
        <NotificationsPage />
      ) : page === 'audit' ? (
        <AuditPage />
      ) : (
        <DevicesPage />
      )}
      <TelemetryStatus />
    </div>
  );
}
