import { lazy, Suspense, useEffect, useState } from 'react';
import { useSession } from './api/hooks.ts';
import { ApproveLinkPage } from './components/ApproveLinkPage.tsx';
import { GuestPanelPage } from './components/GuestPanelPage.tsx';
import { Shell } from './components/Shell.tsx';
import { Login } from './components/Login.tsx';
import { SecureBanner } from './components/SecureBanner.tsx';
import { isKiosk, panelToken } from './panels.ts';

/** The token of an approval link (#/approve/<token>), opened without a session. */
const approveRoute = '#/approve/';

/** A device's web terminal (#/terminal/<device id>), in a tab of its own. */
const terminalRoute = '#/terminal/';

// Loaded on demand: xterm.js is most of its weight.
const TerminalPage = lazy(() => import('./components/TerminalPage.tsx'));

/** The URL hash, kept current. */
function useHash(): string {
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const onHash = () => {
      setHash(window.location.hash);
    };
    window.addEventListener('hashchange', onHash);
    return () => {
      window.removeEventListener('hashchange', onHash);
    };
  }, []);
  return hash;
}

export function App() {
  const hash = useHash();
  // A panel's share link (/p/<token>) needs no session: the link is the credential.
  const panel = panelToken(window.location.pathname);
  if (panel !== null) {
    return <GuestPanelPage token={panel} kiosk={isKiosk(window.location.search)} />;
  }
  if (hash.startsWith(approveRoute)) {
    const token = hash.slice(approveRoute.length);
    return <ApproveLinkPage key={token} token={token} />;
  }
  return (
    <>
      {hash.startsWith(terminalRoute) ? null : <SecureBanner />}
      <Main hash={hash} />
    </>
  );
}

function Main({ hash }: { hash: string }) {
  const session = useSession();

  if (session.isPending) {
    return null;
  }
  if (session.isError) {
    return (
      <main className="login">
        <div className="error-box" role="alert">
          Cannot reach the hub: {session.error.message}
        </div>
      </main>
    );
  }
  if (!session.data) {
    return <Login />;
  }
  if (hash.startsWith(terminalRoute)) {
    const id = decodeURIComponent(hash.slice(terminalRoute.length));
    return (
      <Suspense fallback={null}>
        <TerminalPage key={id} deviceId={id} />
      </Suspense>
    );
  }
  return <Shell />;
}
