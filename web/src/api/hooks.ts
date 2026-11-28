import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import {
  api,
  ApiError,
  streamDeviceLogs,
  subscribeEvents,
  subscribeGuestEvents,
  type PanelInput,
  type AuditFilter,
  type CreateTokenOptions,
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
  type LogLine,
  type MetricsRange,
  type NetworkHostState,
  type PendingToken,
} from './client.ts';
import { useWithReauth } from './reauth.ts';
import { applyScanDone, scanInterrupted, scanStarted, scanTimeoutMs, type NetworkScanState } from '../networkscan.ts';

export const keys = {
  session: ['session'] as const,
  /** Set by a sign-out or a password change some master has not taken yet. */
  signOutNotice: ['sign-out-notice'] as const,
  devices: ['devices'] as const,
  networkHosts: ['network', 'hosts'] as const,
  networkScan: ['network', 'scan'] as const,
  beszelSystems: ['beszel', 'systems'] as const,
  talosNodes: ['talos', 'nodes'] as const,
  tls: ['tls'] as const,
  tailscale: ['tailscale'] as const,
  shareOrigin: ['tls', 'share-origin'] as const,
  configDrift: ['cluster', 'config-drift'] as const,
  metrics: (id: string, range: MetricsRange) => ['metrics', id, range] as const,
  metricsSparklines: ['metrics-sparklines'] as const,
  kubeClusters: ['kube', 'clusters'] as const,
  kubeCluster: (id: string) => ['kube', 'cluster', id] as const,
  notifyChannels: ['notify', 'channels'] as const,
  audit: (filter: AuditFilter) => ['audit', filter] as const,
  auditVerify: ['audit', 'verify'] as const,
  approvals: (status: 'pending' | 'all') => ['approvals', status] as const,
  approvalLink: (token: string) => ['approval-link', token] as const,
  runbooks: ['runbooks', 'list'] as const,
  runbookPlan: (id: string) => ['runbooks', 'plan', id] as const,
  runbookRuns: ['runbooks', 'runs'] as const,
  runbookRun: (id: string) => ['runbooks', 'run', id] as const,
  telemetry: ['telemetry'] as const,
  panels: ['panels'] as const,
  guestPanel: (token: string) => ['guest-panel', token] as const,
  dashboardTokens: ['dashboard-tokens'] as const,
  pendingTokens: ['tokens', 'pending'] as const,
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
  return useQuery({
    queryKey: keys.session,
    queryFn: api.session,
    staleTime: Infinity,
    // The banner of a hub that could not compare sign-ins goes once it has.
    refetchInterval: (q) => (q.state.data?.sign_ins_uncompared ? 30_000 : false),
  });
}

/** What the last sign-out or password change left to tell, if anything. */
export function useSignOutNotice() {
  return useQuery<string | null>({ queryKey: keys.signOutNotice, queryFn: () => null, staleTime: Infinity });
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
    onSuccess: (reach) => {
      qc.setQueryData(keys.signOutNotice, reach?.message ?? null);
    },
    onSettled: () => {
      qc.removeQueries({ queryKey: keys.devices });
      qc.removeQueries({ queryKey: ['network'] });
      qc.removeQueries({ queryKey: ['beszel'] });
      qc.removeQueries({ queryKey: ['talos'] });
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
    initialPageParam: undefined as number | string | undefined,
    getNextPageParam: (last) => last.next_cursor ?? last.next_before,
  });
}

/** The check of every audit seal and chain; it reads the whole log, so not refetched on its own. */
export function useAuditVerify() {
  return useQuery({ queryKey: keys.auditVerify, queryFn: api.auditVerify, staleTime: 60_000 });
}

/** The device list, kept current by the event stream rather than polling. */
export function useDevices() {
  return useQuery({ queryKey: keys.devices, queryFn: api.devices, staleTime: Infinity });
}

/** Hosts network discovery found; refetched on network events and now and then, as scans run on their own schedule. */
export function useNetworkHosts() {
  return useQuery({ queryKey: keys.networkHosts, queryFn: api.networkHosts, refetchInterval: networkHostsRefreshMs });
}

/** What the hub last read from the Talos API; the hub reads it on its own schedule. */
export function useTalosNodes() {
  return useQuery({ queryKey: keys.talosNodes, queryFn: api.talosNodes, refetchInterval: networkHostsRefreshMs });
}

/** What the hub last read from Beszel; the hub reads Beszel on its own schedule. */
export function useBeszelSystems() {
  return useQuery({ queryKey: keys.beszelSystems, queryFn: api.beszelSystems, refetchInterval: networkHostsRefreshMs });
}

/** Marks a host known, ignored or neither, then refetches the hosts. */
export function useMarkNetworkHost() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ mac, state }: { mac: string; state: Exclude<NetworkHostState, 'adopted'> }) =>
      api.markNetworkHost(mac, state),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.networkHosts }),
  });
}

/** Adopts a host under a name, or unadopts it (name null), then refetches the hosts. */
export function useAdoptNetworkHost() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ mac, name }: { mac: string; name: string | null }) =>
      name === null ? api.unadoptNetworkHost(mac) : api.adoptNetworkHost(mac, name),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.networkHosts }),
  });
}

const idleScan: NetworkScanState = { running: false };

/**
 * The state of the network scan asked for from this UI, kept in the query
 * cache: starting a scan sets it running, and the network.scan.done event
 * with its id (useDeviceEvents) sets how it ended. If that event does not
 * come within scanTimeoutMs, it stops running and the hosts are refetched.
 */
export function useNetworkScan() {
  const qc = useQueryClient();
  const state = useQuery<NetworkScanState>({
    queryKey: keys.networkScan,
    queryFn: () => qc.getQueryData<NetworkScanState>(keys.networkScan) ?? idleScan,
    staleTime: Infinity,
  });
  const running = state.data?.running ?? false;
  useEffect(() => {
    if (!running) {
      return;
    }
    const timer = setTimeout(() => {
      qc.setQueryData<NetworkScanState>(keys.networkScan, (old) => old && scanInterrupted(old));
      void qc.invalidateQueries({ queryKey: keys.networkHosts });
    }, scanTimeoutMs);
    return () => {
      clearTimeout(timer);
    };
  }, [qc, running]);
  const start = useMutation({
    mutationFn: api.scanNetwork,
    onMutate: () => {
      // Running before the answer, so a done event that beats it still ends the scan.
      qc.setQueryData<NetworkScanState>(keys.networkScan, { running: true });
    },
    onSuccess: ({ id }) => {
      qc.setQueryData<NetworkScanState>(keys.networkScan, (old) => scanStarted(old ?? idleScan, id));
    },
    onError: (err) => {
      // A scan already running ends with the event all the same.
      if (err instanceof ApiError && err.code === 'scan_running') {
        qc.setQueryData<NetworkScanState>(keys.networkScan, { running: true });
      } else {
        qc.setQueryData<NetworkScanState>(keys.networkScan, idleScan);
      }
    },
  });
  return { state: state.data ?? idleScan, start };
}

/** The admin's answer to the telemetry prompt. */
export function useTelemetry() {
  return useQuery({ queryKey: keys.telemetry, queryFn: api.telemetry, staleTime: Infinity });
}

/** Stores the admin's answer to the telemetry prompt. */
export function useSetTelemetry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (enabled: boolean) => api.setTelemetry(enabled),
    onSuccess: (data) => {
      qc.setQueryData(keys.telemetry, data);
    },
  });
}

/** The hub's node on a tailnet; polled while it starts. */
export function useTailscaleInfo() {
  return useQuery({
    queryKey: keys.tailscale,
    queryFn: api.tailscaleInfo,
    refetchInterval: (q) => (q.state.data?.state === 'starting' ? 5000 : false),
  });
}

/** The hub's HTTPS address details, fetched only when enabled. */
export function useTlsInfo(enabled: boolean) {
  return useQuery({ queryKey: keys.tls, queryFn: api.tlsInfo, staleTime: Infinity, enabled });
}

/**
 * The origin for links and snippets other devices use (MCP, Homepage, panel
 * links): the hub's stable address when this page's host resolves only here
 * (hearth.local, localhost), else this page's origin. Fetched at each mount,
 * as another master may answer hearth.local by now; undefined until then, so
 * a snippet shown once never changes under the user.
 */
export function useShareOrigin(): string | undefined {
  const tls = useQuery({
    queryKey: keys.shareOrigin,
    queryFn: api.tlsInfo,
    gcTime: 0,
    refetchOnWindowFocus: false,
    retry: false,
  });
  if (tls.isPending) {
    return undefined;
  }
  return tls.data?.lan_origin ?? window.location.origin;
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

/** Creates an enrollment token; a hub-eligible one asks for the admin password first. */
export function useCreateToken() {
  const withReauth = useWithReauth();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (opts: CreateTokenOptions = {}) =>
      opts.hub ? withReauth(() => api.createToken(opts)) : api.createToken(opts),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.pendingTokens }),
  });
}

/** A token leaves the list once a device enrolls with it or it expires, so the list is polled. */
const pendingTokensRefreshMs = 15_000;

/** The enrollment tokens not used yet nor expired. */
export function usePendingTokens() {
  return useQuery({ queryKey: keys.pendingTokens, queryFn: api.pendingTokens, refetchInterval: pendingTokensRefreshMs });
}

/** Revokes an unused enrollment token; a hub-eligible one asks for the admin password first. */
export function useRevokeToken() {
  const withReauth = useWithReauth();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (t: PendingToken) => (t.hub ? withReauth(() => api.revokeToken(t.id)) : api.revokeToken(t.id)),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.pendingTokens }),
  });
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
          // A scan's done event may have been sent while the stream was down.
          qc.setQueryData<NetworkScanState>(keys.networkScan, (old) => old && scanInterrupted(old));
          void qc.invalidateQueries({ queryKey: keys.devices });
          void qc.invalidateQueries({ queryKey: ['kube'] });
          void qc.invalidateQueries({ queryKey: keys.networkHosts });
        },
        onNetworkHost: () => {
          void qc.invalidateQueries({ queryKey: keys.networkHosts });
        },
        onNetworkScanDone: (done) => {
          qc.setQueryData<NetworkScanState>(keys.networkScan, (old) => applyScanDone(old ?? idleScan, done));
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
export function useKubeClusters(enabled = true) {
  return useQuery({ queryKey: keys.kubeClusters, queryFn: api.kubeClusters, staleTime: Infinity, enabled });
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

export function useRunbooks(enabled = true) {
  return useQuery({ queryKey: keys.runbooks, queryFn: api.runbooks, enabled });
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

export function usePanels() {
  return useQuery({ queryKey: keys.panels, queryFn: api.panels });
}

/** Creates a panel, or saves an existing one when id is set. */
export function useSavePanel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, panel }: { id?: string; panel: PanelInput }) =>
      id ? api.updatePanel(id, panel) : api.createPanel(panel),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.panels }),
  });
}

export function useDeletePanel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.deletePanel,
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.panels }),
  });
}

export function useCreatePanelLink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, expiresIn }: { id: string; expiresIn: string }) => api.createPanelLink(id, expiresIn),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.panels }),
  });
}

export function useRevokePanelLink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, link }: { id: string; link: string }) => api.revokePanelLink(id, link),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.panels }),
  });
}

export function useDashboardTokens() {
  return useQuery({ queryKey: keys.dashboardTokens, queryFn: api.dashboardTokens });
}

export function useCreateDashboardToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ name, expiresIn }: { name: string; expiresIn: string }) => api.createDashboardToken(name, expiresIn),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.dashboardTokens }),
  });
}

export function useRevokeDashboardToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.revokeDashboardToken,
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.dashboardTokens }),
  });
}

/**
 * A panel through its share link, refetched whenever the hub says an entity
 * on it changed, and whenever the change stream (re)opens. A link the hub no
 * longer knows (404) stops the stream for good.
 */
export function useGuestPanel(token: string) {
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: keys.guestPanel(token),
    queryFn: () => api.guestPanel(token),
    retry: (n, err) => !(err instanceof ApiError && err.status === 404) && n < 3,
  });
  const gone = query.error instanceof ApiError && query.error.status === 404;
  useEffect(() => {
    if (gone) {
      return;
    }
    let close: (() => void) | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const refetch = () => qc.invalidateQueries({ queryKey: keys.guestPanel(token) });
    const connect = () => {
      close = subscribeGuestEvents(token, {
        onOpen: () => void refetch(),
        onChange: () => void refetch(),
        onError: () => {
          void refetch();
          timer = setTimeout(connect, reconnectDelayMs);
        },
      });
    };
    connect();
    return () => {
      clearTimeout(timer);
      close?.();
    };
  }, [qc, token, gone]);
  return query;
}

export function useGuestAction(token: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ widget, action }: { widget: string; action: string }) => api.guestAction(token, widget, action),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.guestPanel(token) }),
  });
}

/** Sends the UI back to the login page when any request finds the session gone. */
export function handleUnauthenticated(qc: QueryClient, err: unknown) {
  if (err instanceof ApiError && err.status === 401) {
    qc.setQueryData(keys.session, null);
  }
}

/** How many lines a log view keeps; older ones are dropped. */
export const maxLogLines = 5000;

export interface DeviceLogs {
  lines: LogLine[];
  /** Lines received since the stream opened, dropped ones included. */
  total: number;
  /** Lines the device dropped because the stream read too slowly. */
  skipped: number;
  /** Whether the first answer (lines or an end) has arrived. */
  open: boolean;
  ended: boolean;
  error?: string;
}

const noLogs: DeviceLogs = { lines: [], total: 0, skipped: 0, open: false, ended: false };

/**
 * Streams a device's log source while mounted, from its last tail lines.
 * Changing an argument or epoch opens a new stream; unmounting closes it,
 * which stops it on the device.
 */
export function useDeviceLogs(device: string, source: string, tail: number, epoch = 0): DeviceLogs {
  const key = [device, source, String(tail), String(epoch)].join('\n');
  const [state, setState] = useState<DeviceLogs & { key: string }>({ ...noLogs, key });
  useEffect(() => {
    // Updates of an older stream are dropped; the first of this one starts afresh.
    const update = (fn: (s: DeviceLogs) => DeviceLogs) => {
      setState((s) => ({ ...fn(s.key === key ? s : noLogs), key }));
    };
    return streamDeviceLogs(device, source, tail, {
      onLines: (lines, skipped) => {
        update((s) => {
          const all = s.lines.concat(lines);
          return {
            ...s,
            open: true,
            lines: all.length > maxLogLines ? all.slice(-maxLogLines) : all,
            total: s.total + lines.length,
            skipped: s.skipped + skipped,
          };
        });
      },
      onEnd: (error) => {
        update((s) => ({ ...s, open: true, ended: true, error }));
      },
    });
  }, [device, source, tail, key]);
  return state.key === key ? state : noLogs;
}
