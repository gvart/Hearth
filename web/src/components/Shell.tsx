import { useEffect, useState } from 'react';
import { useDeviceEvents, useLogout } from '../api/hooks.ts';
import { DevicesPage } from './DevicesPage.tsx';
import { KubernetesPage } from './KubernetesPage.tsx';
import { Logo } from './Logo.tsx';

type Page = 'devices' | 'kubernetes';

const pages: { id: Page; label: string; hash: string }[] = [
  { id: 'devices', label: 'Devices', hash: '#/' },
  { id: 'kubernetes', label: 'Kubernetes', hash: '#/kubernetes' },
];

function pageOf(hash: string): Page {
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
              <a key={p.id} href={p.hash} className="nav-link" aria-current={page === p.id ? 'page' : undefined}>
                {p.label}
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
      {page === 'kubernetes' ? <KubernetesPage /> : <DevicesPage />}
    </div>
  );
}
