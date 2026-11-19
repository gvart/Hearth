import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { useEffect, useRef } from 'react';
import {
  api,
  ApiError,
  subscribeEvents,
  type AuditFilter,
  type Device,
  type DeviceEvent,
  type KubeActionRequest,
  type KubeChange,
  type KubeCluster,
  type KubeEvent,
  type KubeNamespace,
  type KubeNode,
  type KubePod,
  type KubeSnapshot,
  type KubeWorkload,
  type MetricsRange,
  type NetworkHostState,
} from './client.ts';

export const keys = {
  session: ['session'] as const,
  devices: ['devices'] as const,
  networkHosts: ['network', 'hosts'] as const,
  beszelSystems: ['beszel', 'systems'] as const,
  tls: ['tls'] as const,
  configDrift: ['cluster', 'config-drift'] as const,
  metrics: (id: string, range: MetricsRange) => ['metrics', id, range] as const,
  metricsSparklines: ['metrics-sparklines'] as const,
  kubeClusters: ['kube', 'clusters'] as const,
  kubeCluster: (id: string) => ['kube', 'cluster', id] as const,
  notifyChannels: ['notify', 'channels'] as const,
  audit: (filter: AuditFilter) => ['audit', filter] as const,
  approvals: (status: 'pending' | 'all') => ['approvals', status] as const,
  approvalLink: (token: string) => ['approval-link', token] as const,
  runbooks: ['runbooks', 'list'] as const,
  runbookPlan: (id: string) => ['runbooks', 'plan', id] as const,
  runbookRuns: ['runbooks', 'runs'] as const,
  runbookRun: (id: string) => ['runbooks', 'run', id] as const,
};

/** A run moves on by itself on the hub, so it is polled until it has ended. */
const runbookRunRefreshMs = 1500;
const runbookRunsRefreshMs = 5000;

/** Approvals change on other hubs and in automations, so they are polled. */
const approvalsRefreshMs = 5000;

/**
 * How often metrics are refetched, and how long a fetched answer counts as
 * fresh so that a remount cannot refetch sooner; the metrics hooks also skip
 * the refetch on window focus and reconnect. Agents send a sample every 15 s,
 * so polling faster would show nothing new.
 */
const metricsRefreshMs = 15_000;

const networkHostsRefreshMs = 60_000;

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
      qc.removeQueries({ queryKey: ['network'] });
      qc.removeQueries({ queryKey: ['beszel'] });
      qc.removeQueries({ queryKey: ['kube'] });
      qc.removeQueries({ queryKey: ['proxmox'] });
      qc.removeQueries({ queryKey: ['audit'] });
      qc.removeQueries({ queryKey: ['approvals'] });
      qc.setQueryData(keys.session, null);
    },
  });
}

/** The audit log under filter, newest first, a page at a time. */
export function useAudit(filter: AuditFilter) {
  return useInfiniteQuery({
    queryKey: keys.audit(filter),
    queryFn: ({ pageParam }) => api.audit(filter, pageParam),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => last.next_before,
  });
}

/** The device list, kept current by the event stream rather than polling. */
export function useDevices() {
  return useQuery({ queryKey: keys.devices, queryFn: api.devices, staleTime: Infinity });
}

/** Hosts network discovery found; refetched on network events and now and then, as scans run on their own schedule. */
export function useNetworkHosts() {
  return useQuery({ queryKey: keys.networkHosts, queryFn: api.networkHosts, refetchInterval: networkHostsRefreshMs });
}

/** What the hub last read from Beszel; the hub reads Beszel on its own schedule. */
export function useBeszelSystems() {
  return useQuery({ queryKey: keys.beszelSystems, queryFn: api.beszelSystems, refetchInterval: networkHostsRefreshMs });
}

/** Marks a host known, ignored or neither, then refetches the hosts. */
export function useMarkNetworkHost() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ mac, state }: { mac: string; state: NetworkHostState }) => api.markNetworkHost(mac, state),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.networkHosts }),
  });
}

/** The hub's HTTPS address details, fetched only when enabled. */
export function useTlsInfo(enabled: boolean) {
  return useQuery({ queryKey: keys.tls, queryFn: api.tlsInfo, staleTime: Infinity, enabled });
}

/** Whether the cluster's hubs run the same per-hub configuration, polled while signed in. */
export function useConfigDrift() {
  return useQuery({ queryKey: keys.configDrift, queryFn: api.configDrift, refetchInterval: 30_000 });
}

/** A device's chart series over range, refreshed while mounted; the last range stays up while the next loads. */
export function useDeviceMetrics(id: string, range: MetricsRange) {
  return useQuery({
    queryKey: keys.metrics(id, range),
    queryFn: () => api.deviceMetrics(id, range),
    refetchInterval: metricsRefreshMs,
    staleTime: metricsRefreshMs,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    placeholderData: keepPreviousData,
  });
}

/** Every device's sparklines from one request, refreshed while mounted. */
export function useMetricsSparklines() {
  return useQuery({
    queryKey: keys.metricsSparklines,
    queryFn: api.metricsSparklines,
    refetchInterval: metricsRefreshMs,
    staleTime: metricsRefreshMs,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
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
          void qc.invalidateQueries({ queryKey: keys.networkHosts });
        },
        onNetworkHost: () => {
          void qc.invalidateQueries({ queryKey: keys.networkHosts });
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

/** The dry run of a Kubernetes action: what it would do, read from the cluster. */
export function useKubeActionPlan(cluster: string, req: KubeActionRequest, enabled: boolean) {
  return useQuery({
    queryKey: ['kube', 'plan', cluster, req] as const,
    queryFn: () => api.kubeAction(cluster, { ...req, dry_run: true }),
    staleTime: 0,
    gcTime: 0,
    retry: false,
    enabled,
  });
}

/**
 * Carries out a Kubernetes action. The cluster's changes reach the page
 * through the event stream.
 */
export function useKubeAction(cluster: string) {
  return useMutation({ mutationFn: (req: KubeActionRequest) => api.kubeAction(cluster, { ...req, dry_run: false }) });
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

/** The hub's notification channels, by name and type. */
export function useNotifyChannels() {
  return useQuery({ queryKey: keys.notifyChannels, queryFn: api.notifyChannels });
}

export function useTestNotifyChannel() {
  return useMutation({ mutationFn: api.testNotifyChannel });
}

/** Pending approvals, or all of them, polled while mounted. */
export function useApprovals(status: 'pending' | 'all') {
  return useQuery({
    queryKey: keys.approvals(status),
    queryFn: () => api.approvals(status),
    refetchInterval: approvalsRefreshMs,
  });
}

/** Approves (with the admin password) or denies (without) a held action. */
export function useDecideApproval() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (d: { id: string; approve: true; password: string } | { id: string; approve: false }) =>
      d.approve ? api.approveApproval(d.id, d.password) : api.denyApproval(d.id),
    onSettled: () => qc.invalidateQueries({ queryKey: ['approvals'] }),
  });
}

/** The approval an approval link is for, read once. */
export function useApprovalLink(token: string) {
  return useQuery({
    queryKey: keys.approvalLink(token),
    queryFn: () => api.approvalLink(token),
    retry: false,
    staleTime: Infinity,
  });
}

export function useDenyApprovalLink(token: string) {
  return useMutation({ mutationFn: () => api.denyApprovalLink(token) });
}

export function useRunbooks() {
  return useQuery({ queryKey: keys.runbooks, queryFn: api.runbooks });
}

/** The plan of a runbook, fetched anew each time it is opened. */
export function useRunbookPlan(id: string, enabled: boolean) {
  return useQuery({ queryKey: keys.runbookPlan(id), queryFn: () => api.runbookPlan(id), enabled, staleTime: 0, gcTime: 0 });
}

export function useRunbookRuns() {
  return useQuery({ queryKey: keys.runbookRuns, queryFn: api.runbookRuns, refetchInterval: runbookRunsRefreshMs });
}

export function useRunbookRun(id: string) {
  return useQuery({
    queryKey: keys.runbookRun(id),
    queryFn: () => api.runbookRun(id),
    refetchInterval: (q) => {
      const status = q.state.data?.status;
      return status === 'succeeded' || status === 'rolled_back' ? false : runbookRunRefreshMs;
    },
  });
}

export function useStartRunbook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.startRunbook,
    onSettled: () => qc.invalidateQueries({ queryKey: keys.runbookRuns }),
  });
}

/** Answers, retries or rolls back a run, then shows where the run is now. */
export function useRunbookRunAction<T>(id: string, act: (vars: T) => Promise<unknown>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: act,
    onSettled: () =>
      Promise.all([
        qc.invalidateQueries({ queryKey: keys.runbookRun(id) }),
        qc.invalidateQueries({ queryKey: keys.runbookRuns }),
      ]),
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
