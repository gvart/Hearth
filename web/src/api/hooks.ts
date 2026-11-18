import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { useEffect, useRef } from 'react';
import { api, ApiError, subscribeEvents, type Device, type DeviceEvent } from './client.ts';

export const keys = {
  session: ['session'] as const,
  devices: ['devices'] as const,
  tls: ['tls'] as const,
  metrics: (id: string) => ['metrics', id] as const,
};

const metricsRefreshMs = 30_000;

const reconnectDelayMs = 2000;

export function useSession() {
  return useQuery({ queryKey: keys.session, queryFn: api.session, staleTime: Infinity });
}

export function useLogin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.login,
    onSuccess: (session) => {
      qc.setQueryData(keys.session, session);
    },
  });
}

export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.logout,
    onSettled: () => {
      qc.removeQueries({ queryKey: keys.devices });
      qc.setQueryData(keys.session, null);
    },
  });
}

/** The device list, kept current by the event stream rather than polling. */
export function useDevices() {
  return useQuery({ queryKey: keys.devices, queryFn: api.devices, staleTime: Infinity });
}

/** The hub's HTTPS address details, fetched only when enabled. */
export function useTlsInfo(enabled: boolean) {
  return useQuery({ queryKey: keys.tls, queryFn: api.tlsInfo, staleTime: Infinity, enabled });
}

/** A device's chart series, refreshed while mounted. */
export function useDeviceMetrics(id: string) {
  return useQuery({
    queryKey: keys.metrics(id),
    queryFn: () => api.deviceMetrics(id),
    refetchInterval: metricsRefreshMs,
  });
}

export function useCreateToken() {
  return useMutation({ mutationFn: api.createToken });
}

/** Applies one server-sent event to the cached device list. */
export function applyEvent(devices: Device[] | undefined, ev: DeviceEvent): Device[] | undefined {
  if (!devices) {
    return devices;
  }
  const i = devices.findIndex((d) => d.id === ev.device.id);
  if (i === -1) {
    return [...devices, ev.device];
  }
  const next = devices.slice();
  next[i] = ev.device;
  return next;
}

/**
 * Streams device events into the query cache while mounted. Whenever the
 * stream (re)opens the list is refetched, so nothing missed while it was down
 * stays stale; when it breaks, the session is rechecked and it reconnects.
 */
export function useDeviceEvents(onEvent?: (ev: DeviceEvent) => void) {
  const qc = useQueryClient();
  const onEventRef = useRef(onEvent);
  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);
  useEffect(() => {
    let close: (() => void) | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const connect = () => {
      close = subscribeEvents({
        onOpen: () => {
          void qc.invalidateQueries({ queryKey: keys.devices });
        },
        onEvent: (ev) => {
          qc.setQueryData<Device[]>(keys.devices, (old) => applyEvent(old, ev));
          onEventRef.current?.(ev);
        },
        onError: () => {
          void qc.invalidateQueries({ queryKey: keys.session });
          timer = setTimeout(connect, reconnectDelayMs);
        },
      });
    };
    connect();
    return () => {
      clearTimeout(timer);
      close?.();
    };
  }, [qc]);
}

/** Sends the UI back to the login page when any request finds the session gone. */
export function handleUnauthenticated(qc: QueryClient, err: unknown) {
  if (err instanceof ApiError && err.status === 401) {
    qc.setQueryData(keys.session, null);
  }
}
