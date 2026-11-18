import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { useEffect, useRef } from 'react';
import {
  api,
  ApiError,
  subscribeEvents,
  type Device,
  type DeviceEvent,
  type KubeChange,
  type KubeCluster,
  type KubeEvent,
  type KubeNamespace,
  type KubeNode,
  type KubePod,
  type KubeSnapshot,
  type KubeWorkload,
} from './client.ts';

export const keys = {
  session: ['session'] as const,
  devices: ['devices'] as const,
  tls: ['tls'] as const,
  metrics: (id: string) => ['metrics', id] as const,
  kubeClusters: ['kube', 'clusters'] as const,
  kubeCluster: (id: string) => ['kube', 'cluster', id] as const,
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
      qc.removeQueries({ queryKey: ['kube'] });
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
          void qc.invalidateQueries({ queryKey: ['kube'] });
        },
        onKubeCluster: (c) => {
          applyKubeCluster(qc, c);
        },
        onKubeChange: (c) => {
          qc.setQueryData<KubeSnapshot>(keys.kubeCluster(c.cluster), (old) => applyKubeChange(old, c));
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

/** The adopted Kubernetes clusters, kept current by the event stream. */
export function useKubeClusters() {
  return useQuery({ queryKey: keys.kubeClusters, queryFn: api.kubeClusters, staleTime: Infinity });
}

/** One cluster's nodes, workloads, pods and events, kept current by the event stream. */
export function useKubeCluster(id: string | undefined) {
  return useQuery({
    queryKey: keys.kubeCluster(id ?? ''),
    queryFn: () => api.kubeCluster(id ?? ''),
    staleTime: Infinity,
    enabled: id !== undefined,
  });
}

/** A pod container's recent log lines, read on demand (not streamed). */
export function useKubePodLogs(opts: { cluster: string; namespace: string; pod: string; container: string; tail: number }) {
  return useQuery({
    queryKey: ['kube', 'logs', opts.cluster, opts.namespace, opts.pod, opts.container, opts.tail] as const,
    queryFn: () => api.kubePodLogs(opts),
    staleTime: Infinity,
    gcTime: 0,
    retry: false,
  });
}

export function useAddKubeCluster() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.addKubeCluster,
    onSuccess: (c) => {
      applyKubeCluster(qc, c);
    },
  });
}

export function useRemoveKubeCluster() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.removeKubeCluster,
    onSuccess: (_, id) => {
      qc.setQueryData<KubeCluster[]>(keys.kubeClusters, (old) => old?.filter((c) => c.id !== id));
      qc.removeQueries({ queryKey: keys.kubeCluster(id) });
    },
  });
}

/** Applies a kube.cluster event (or a just-added cluster) to the cache. */
function applyKubeCluster(qc: QueryClient, c: KubeCluster) {
  qc.setQueryData<KubeCluster[]>(keys.kubeClusters, (old) => {
    if (!old) {
      return old;
    }
    const rest = old.filter((o) => o.id !== c.id);
    return c.removed ? rest : [...rest, c].sort((a, b) => a.name.localeCompare(b.name));
  });
  if (c.removed) {
    qc.removeQueries({ queryKey: keys.kubeCluster(c.id) });
    return;
  }
  const snap = qc.getQueryData<KubeSnapshot>(keys.kubeCluster(c.id));
  if (snap && snap.cluster.state !== 'connected' && c.state === 'connected') {
    // Just synced: the whole state is new.
    void qc.invalidateQueries({ queryKey: keys.kubeCluster(c.id) });
  } else if (snap) {
    qc.setQueryData<KubeSnapshot>(keys.kubeCluster(c.id), { ...snap, cluster: c });
  }
}

/** The key of an entity within its kind, as the hub names it in a KubeChange. */
export function kubeKey(kind: KubeChange['kind'], o: NonNullable<KubeChange['object']>): string {
  switch (kind) {
    case 'node':
    case 'namespace':
      return (o as KubeNode | KubeNamespace).name;
    case 'pod': {
      const p = o as KubePod;
      return `${p.namespace}/${p.name}`;
    }
    case 'workload': {
      const w = o as KubeWorkload;
      return `${w.kind}/${w.namespace}/${w.name}`;
    }
    case 'event':
      return (o as KubeEvent).uid;
  }
}

const maxEvents = 200;

function upsert<T>(list: T[], kind: KubeChange['kind'], c: KubeChange): T[] {
  const rest = list.filter((o) => kubeKey(kind, o as NonNullable<KubeChange['object']>) !== c.key);
  return c.op === 'delete' || !c.object ? rest : [...rest, c.object as T];
}

const byName = (a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name);
const byNsName = (a: { namespace: string; name: string }, b: { namespace: string; name: string }) =>
  a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name);

/** Applies one kube.object event to a cached cluster snapshot. */
export function applyKubeChange(snap: KubeSnapshot | undefined, c: KubeChange): KubeSnapshot | undefined {
  if (!snap) {
    return snap;
  }
  switch (c.kind) {
    case 'node':
      return { ...snap, nodes: upsert(snap.nodes, c.kind, c).sort(byName) };
    case 'namespace':
      return { ...snap, namespaces: upsert(snap.namespaces, c.kind, c).sort(byName) };
    case 'workload':
      return { ...snap, workloads: upsert(snap.workloads, c.kind, c).sort(byNsName) };
    case 'pod':
      return { ...snap, pods: upsert(snap.pods, c.kind, c).sort(byNsName) };
    case 'event':
      return {
        ...snap,
        events: upsert(snap.events, c.kind, c)
          .sort((a, b) => b.last.localeCompare(a.last))
          .slice(0, maxEvents),
      };
  }
}

/** Sends the UI back to the login page when any request finds the session gone. */
export function handleUnauthenticated(qc: QueryClient, err: unknown) {
  if (err instanceof ApiError && err.status === 401) {
    qc.setQueryData(keys.session, null);
  }
}
