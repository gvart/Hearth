// Typed client and hooks for a device's Docker or Podman containers (/api/v1/devices/{id}/docker).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { request, type LogLine } from './client.ts';

export interface DockerContainer {
  id: string;
  name: string;
  image: string;
  /** The engine's word: running, exited, created, paused, restarting, dead. */
  state: string;
  /** The engine's summary, such as "Up 2 hours". */
  status: string;
  /** Its Compose service; empty outside a project. */
  service: string;
  created: string | null;
}

/** A Compose project: the containers labelled with it. */
export interface DockerStack {
  project: string;
  running: number;
  containers: DockerContainer[];
}

export interface DockerImage {
  id: string;
  tags: string[];
  size_bytes: number;
  created: string | null;
}

export interface DockerSnapshot {
  stacks: DockerStack[];
  /** Containers outside any Compose project. */
  containers: DockerContainer[];
  images: DockerImage[];
  /** The agent left containers or images out to keep the answer bounded. */
  truncated: boolean;
}

export interface DockerLogs {
  lines: LogLine[];
  /** Lines before these were left out. */
  truncated: boolean;
}

export type DockerActionName = 'start' | 'stop' | 'restart';

export interface DockerActionResult {
  action: DockerActionName;
  container: string;
  result: string;
}

/** The most log lines the hub reads. */
export const maxDockerLogTail = 200;

const base = (device: string) => `/devices/${encodeURIComponent(device)}/docker`;

const dockerApi = {
  list: (device: string) => request<DockerSnapshot>('GET', base(device)),
  logs: (device: string, container: string, tail: number) =>
    request<DockerLogs>('GET', `${base(device)}/logs?container=${encodeURIComponent(container)}&tail=${String(tail)}`),
  act: (device: string, action: DockerActionName, container: string) =>
    request<DockerActionResult>('POST', `${base(device)}/actions`, { action, container }),
};

const keys = {
  list: (device: string) => ['docker', device] as const,
  logs: (device: string, container: string, tail: number) => ['docker-logs', device, container, tail] as const,
};

/**
 * The device's containers, asked of its agent. Every read is audited on the
 * hub, so this never polls or refetches on focus: it reads once per opening
 * of the device page, after an action, and on refetch().
 */
export function useDocker(device: string) {
  return useQuery({
    queryKey: keys.list(device),
    queryFn: () => dockerApi.list(device),
    staleTime: Infinity,
    gcTime: 0,
    refetchOnWindowFocus: false,
    retry: false,
  });
}

/** The last lines of a container's log, read once (audited), and again on refetch(). */
export function useDockerLogs(device: string, container: string, tail: number) {
  return useQuery({
    queryKey: keys.logs(device, container, tail),
    queryFn: () => dockerApi.logs(device, container, tail),
    staleTime: Infinity,
    gcTime: 0,
    refetchOnWindowFocus: false,
    retry: false,
  });
}

/** Starts, stops or restarts a container; answers once policy decided and the engine did it. */
export function useDockerAction(device: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: { action: DockerActionName; container: string }) =>
      dockerApi.act(device, req.action, req.container),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: keys.list(device) });
    },
  });
}
