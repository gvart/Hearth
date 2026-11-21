import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { handleUnauthenticated } from './api/hooks.ts';
import { App } from './App.tsx';
import { applyTheme, storedTheme } from './theme.ts';
// Stylesheet order: tokens, the app's layout rules, then the Blueprint look. The two pages loaded on
// demand bring their stylesheets later, so those are imported here to keep the look last.
import './styles/tokens.css';
import './index.css';
import './components/AutomationsPage.css';
import './components/TerminalPage.css';
import './styles/blueprint.css';

applyTheme(storedTheme());

const container = document.getElementById('root');
if (!container) {
  throw new Error('root element #root not found');
}

const queryClient: QueryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (err) => {
      handleUnauthenticated(queryClient, err);
    },
  }),
  mutationCache: new MutationCache({
    onError: (err) => {
      handleUnauthenticated(queryClient, err);
    },
  }),
  defaultOptions: {
    // Live data arrives over the event stream; no background polling.
    queries: { retry: 1, refetchOnWindowFocus: false },
  },
});

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);

// Browsers allow service workers (and installing the app) only in a secure
// context: https, or http://localhost.
if ('serviceWorker' in navigator && window.isSecureContext && import.meta.env.PROD) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch((err: unknown) => {
      console.warn('service worker registration failed', err);
    });
  });
}
