// Typed client and hooks for adopted ESPHome devices (/api/v1/esphome).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { request } from './client.ts';

export type ESPHomeState = 'connecting' | 'connected' | 'unavailable';

export interface ESPHomeDevice {
  id: string;
  name: string;
  /** The IP and port the hub connects to. */
  address: string;
  encryption: 'noise' | 'plaintext';
  /** Whether switch and button calls are allowed: off means read-only. */
  control: boolean;
  state: ESPHomeState;
  error: string;
  created_at: string;
  /** What the device said of itself on the last connection. */
  device_name: string;
  friendly_name: string;
  mac: string;
  esphome_version: string;
  model: string;
  manufacturer: string;
  entities: number;
}

export type ESPHomeEntityKind = 'sensor' | 'binary_sensor' | 'switch' | 'button' | 'text_sensor';

export interface ESPHomeEntity {
  key: number;
  object_id: string;
  name: string;
  kind: ESPHomeEntityKind;
  unit?: string;
  device_class?: string;
  accuracy_decimals?: number;
  /** A number, a boolean or text; null while the device has none. */
  state: number | boolean | string | null;
}

export interface ESPHomeSnapshot {
  device: ESPHomeDevice;
  entities: ESPHomeEntity[];
  /** The policy class of esphome.call. */
  call_class: string;
}

export interface AddESPHomeDevice {
  name: string;
  address: string;
  key: string;
  password: string;
  control: boolean;
}

export type ESPHomeCallAction = 'on' | 'off' | 'press';

export interface ESPHomeCallResult {
  action: ESPHomeCallAction;
  class: string;
  target: string;
  result: string;
}

const esphomeApi = {
  devices: async () => (await request<{ devices: ESPHomeDevice[] }>('GET', '/esphome/devices')).devices,
  device: (id: string) => request<ESPHomeSnapshot>('GET', `/esphome/devices/${encodeURIComponent(id)}`),
  add: (opts: AddESPHomeDevice) => request<ESPHomeDevice>('POST', '/esphome/devices', opts),
  remove: (id: string) => request<undefined>('DELETE', `/esphome/devices/${encodeURIComponent(id)}`),
  call: (device: string, key: number, action: ESPHomeCallAction) =>
    request<ESPHomeCallResult>('POST', `/esphome/devices/${encodeURIComponent(device)}/call`, { key, action }),
};

const keys = {
  all: ['esphome'] as const,
  devices: ['esphome', 'devices'] as const,
  device: (id: string) => ['esphome', 'device', id] as const,
};

/** The hub holds each device's states live; the page reads them this often. */
const deviceRefreshMs = 2000;
const listRefreshMs = 5000;

export function useESPHomeDevices(enabled = true) {
  return useQuery({ queryKey: keys.devices, queryFn: esphomeApi.devices, refetchInterval: listRefreshMs, enabled });
}

export function useESPHomeDevice(id: string) {
  return useQuery({ queryKey: keys.device(id), queryFn: () => esphomeApi.device(id), refetchInterval: deviceRefreshMs });
}

export function useAddESPHomeDevice() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: esphomeApi.add,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.all });
    },
  });
}

export function useRemoveESPHomeDevice() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: esphomeApi.remove,
    onSuccess: (_, id) => {
      qc.removeQueries({ queryKey: keys.device(id) });
      void qc.invalidateQueries({ queryKey: keys.devices });
    },
  });
}

/** Turns a switch on or off or presses a button, once policy allowed it. */
export function useESPHomeCall(device: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: { key: number; action: ESPHomeCallAction }) => esphomeApi.call(device, req.key, req.action),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: keys.device(device) });
    },
  });
}
