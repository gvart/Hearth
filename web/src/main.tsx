import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { handleUnauthenticated } from './api/hooks.ts';
import { App } from './App.tsx';
import './index.css';

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
