// Re-authentication before sensitive actions: the hub refuses them with
// reauth_required unless the session entered the admin password again in
// the last few minutes (POST /api/v1/session/reauth).

import { useQueryClient } from '@tanstack/react-query';
import { useCallback, useSyncExternalStore } from 'react';
import { ApiError, request, type Session } from './client.ts';
import { keys } from './hooks.ts';

export interface Reauthed {
  reauth_until: string;
}

/** Sends the admin password; a wrong one is a 403 reauth_failed, too many a 429. */
export const reauthenticate = (password: string) => request<Reauthed>('POST', '/session/reauth', { password });

type Waiter = { resolve: () => void; reject: (err: Error) => void };

// The one password prompt of the app: ReauthDialog shows it while a waiter is set.
let waiter: Waiter | null = null;
const listeners = new Set<() => void>();

function setWaiter(w: Waiter | null) {
  waiter = w;
  for (const l of listeners) {
    l();
  }
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => {
    listeners.delete(l);
  };
}

/** The pending prompt, for ReauthDialog. */
export function useReauthPrompt(): Waiter | null {
  return useSyncExternalStore(subscribe, () => waiter);
}

/** Ends the pending prompt: resolve once the password was accepted, reject on cancel. */
export function settleReauthPrompt(ok: boolean) {
  const w = waiter;
  setWaiter(null);
  if (ok) {
    w?.resolve();
  } else {
    w?.reject(new ApiError(403, 'reauth_cancelled', 'Cancelled: the action needs your password.'));
  }
}

function prompt(): Promise<void> {
  // A second sensitive action while one prompt is open waits for the same one.
  if (waiter) {
    const prev = waiter;
    return new Promise((resolve, reject) => {
      setWaiter({
        resolve: () => {
          prev.resolve();
          resolve();
        },
        reject: (e) => {
          prev.reject(e);
          reject(e);
        },
      });
    });
  }
  return new Promise((resolve, reject) => {
    setWaiter({ resolve, reject });
  });
}

/** Whether the session's last entry of the password still covers sensitive actions. */
function reauthValid(session: Session | null | undefined): boolean {
  const until = session?.reauth_until;
  // A few seconds of margin for clock skew and the request's own time.
  return until !== undefined && Date.parse(until) - Date.now() > 5000;
}

/**
 * Runs a sensitive action: asks for the admin password first unless the
 * session entered it lately, and again if the hub still refuses it with
 * reauth_required.
 */
export function useWithReauth() {
  const qc = useQueryClient();
  return async function withReauth<T>(fn: () => Promise<T>): Promise<T> {
    if (!reauthValid(qc.getQueryData<Session | null>(keys.session))) {
      await prompt();
    }
    try {
      return await fn();
    } catch (err) {
      if (!(err instanceof ApiError && err.code === 'reauth_required')) {
        throw err;
      }
      await prompt();
      return fn();
    }
  };
}

/**
 * Forgets the cached re-authentication, as the hub refused one it no longer
 * holds (it restarted): the next sensitive action asks for the password.
 */
export function useForgetReauth() {
  const qc = useQueryClient();
  return useCallback(() => {
    qc.setQueryData<Session | null>(keys.session, (s) => (s ? { ...s, reauth_until: undefined } : s));
  }, [qc]);
}

/** Records a re-authentication in the cached session, so the next sensitive action asks no password. */
export function useRememberReauth() {
  const qc = useQueryClient();
  return (r: Reauthed) => {
    qc.setQueryData<Session | null>(keys.session, (s) => (s ? { ...s, reauth_until: r.reauth_until } : s));
  };
}
