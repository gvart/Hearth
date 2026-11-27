// Typed client and hooks for upgrading a device's agent from the hub
// (POST /api/v1/devices/{id}/upgrade, #347).

import { useMutation, useQuery } from '@tanstack/react-query';
import { request, type Device } from './client.ts';
import { useWithReauth } from './reauth.ts';

/** The answer to an upgrade: the agent replaced its binary and restarts with it. */
export interface Upgraded {
  version: string;
  from?: string;
}

export const upgradeApi = {
  /** A device as its own page sees it: with the installer's command for an agent too old to upgrade itself. */
  device: (id: string) => request<Device>('GET', `/devices/${encodeURIComponent(id)}`),
  /** Upgrades the device's agent to version, or to the hub's own. */
  upgrade: (id: string, version?: string) =>
    request<Upgraded>('POST', `/devices/${encodeURIComponent(id)}/upgrade`, version ? { version } : {}),
};

/** The device as its own page sees it, only while enabled. */
export function useDeviceDetail(id: string, enabled: boolean) {
  return useQuery({ queryKey: ['devices', id, 'detail'], queryFn: () => upgradeApi.device(id), enabled });
}

/** Upgrades the device's agent to a release, or to the hub's own: dangerous, with the password again. */
export function useUpgradeDevice(id: string) {
  const withReauth = useWithReauth();
  return useMutation({ mutationFn: (version?: string) => withReauth(() => upgradeApi.upgrade(id, version)) });
}
