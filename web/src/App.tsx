import { useEffect, useState } from 'react';
import { useSession } from './api/hooks.ts';
import { ApproveLinkPage } from './components/ApproveLinkPage.tsx';
import { Shell } from './components/Shell.tsx';
import { Login } from './components/Login.tsx';
import { SecureBanner } from './components/SecureBanner.tsx';

/** The token of an approval link (#/approve/<token>), opened without a session. */
const approveRoute = '#/approve/';

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
  if (hash.startsWith(approveRoute)) {
    const token = hash.slice(approveRoute.length);
    return <ApproveLinkPage key={token} token={token} />;
  }
  return (
    <>
      <SecureBanner />
      <Main />
    </>
  );
}

function Main() {
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
  return session.data ? <Shell /> : <Login />;
}
