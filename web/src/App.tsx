import { useSession } from './api/hooks.ts';
import { DevicesPage } from './components/DevicesPage.tsx';
import { Login } from './components/Login.tsx';
import { SecureBanner } from './components/SecureBanner.tsx';

export function App() {
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
  return session.data ? <DevicesPage /> : <Login />;
}
