// Typed client and hooks for Device Protocol devices: their commands
// (POST /api/v1/devices/{id}/commands) and their removal
// (DELETE /api/v1/devices/{id}). Both are dangerous: the password again.

import { useMutation, useQueryClient } from '@tanstack/react-query';
import { request } from './client.ts';
import { keys } from './hooks.ts';
import { useWithReauth } from './reauth.ts';

/** A device's answer to a command. A 502 carries it too, as the ApiError's body, when the device says it failed. */
export interface ProtocolCommandResult {
  id: string;
  command: string;
  class: string;
  ok: boolean;
  message?: string;
}

export interface ProtocolRemoveResult {
  id: string;
  /** Whether this hub's clients file had the device's MQTT user, now removed. */
  mqtt_user_removed: boolean;
  class: string;
}

const protocolApi = {
  command: (device: string, command: string, params?: Record<string, unknown>) =>
    request<ProtocolCommandResult>('POST', `/devices/${encodeURIComponent(device)}/commands`, { command, params }),
  remove: (device: string) => request<ProtocolRemoveResult>('DELETE', `/devices/${encodeURIComponent(device)}`),
};

/** Sends device one of the commands it announced, with the password again. */
export function useProtocolCommand(device: string) {
  const withReauth = useWithReauth();
  return useMutation({
    mutationFn: ({ command, params }: { command: string; params?: Record<string, unknown> }) =>
      withReauth(() => protocolApi.command(device, command, params)),
  });
}

/**
 * Removes a Device Protocol device and its MQTT user on this hub, with the
 * password again. No event tells of a removed device: once its result was
 * shown, call forget, which reads the devices again.
 */
export function useRemoveProtocolDevice() {
  const withReauth = useWithReauth();
  const qc = useQueryClient();
  const forget = () => qc.invalidateQueries({ queryKey: keys.devices });
  const m = useMutation({
    mutationFn: (device: string) => withReauth(() => protocolApi.remove(device)),
    onError: forget,
  });
  return { ...m, forget };
}
