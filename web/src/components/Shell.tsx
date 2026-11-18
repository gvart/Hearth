import { useEffect, useRef, useState } from 'react';
import { useApprovals, useDeviceEvents, useLogout } from '../api/hooks.ts';
import { ApprovalsPage } from './ApprovalsPage.tsx';
import { AuditPage } from './AuditPage.tsx';
import { ConfigDriftBanner } from './ConfigDriftBanner.tsx';
import { DevicesPage } from './DevicesPage.tsx';
import { KubernetesPage } from './KubernetesPage.tsx';
import { Logo } from './Logo.tsx';
import { NotificationsPage } from './NotificationsPage.tsx';

type Page = 'devices' | 'kubernetes' | 'notifications' | 'audit' | 'approvals';

const pages: { id: Page; label: string; hash: string }[] = [
  { id: 'devices', label: 'Devices', hash: '#/' },
  { id: 'kubernetes', label: 'Kubernetes', hash: '#/kubernetes' },
  { id: 'notifications', label: 'Notifications', hash: '#/notifications' },
  { id: 'audit', label: 'Audit', hash: '#/audit' },
  { id: 'approvals', label: 'Approvals', hash: '#/approvals' },
];

function pageOf(hash: string): Page {
  if (hash.startsWith('#/approvals')) {
    return 'approvals';
  }
  if (hash.startsWith('#/notifications')) {
    return 'notifications';
  }
  if (hash.startsWith('#/audit')) {
    return 'audit';
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
  const activeLink = useRef<HTMLAnchorElement>(null);

  // On a phone the links scroll sideways: keep the current page's link in view,
  // also when the waiting badge widens it.
  useEffect(() => {
    activeLink.current?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }, [page, waiting]);

  return (
    <div className="app">
      <header className="topbar">
        <div className="topbar-left">
          <div className="brand">
            <Logo size={28} />
            <span>Hearth</span>
          </div>
          <nav className="nav" aria-label="Sections">
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
      {page === 'approvals' ? (
        <ApprovalsPage />
      ) : page === 'kubernetes' ? (
        <KubernetesPage />
      ) : page === 'notifications' ? (
        <NotificationsPage />
      ) : page === 'audit' ? (
        <AuditPage />
      ) : (
        <DevicesPage />
      )}
    </div>
  );
}
