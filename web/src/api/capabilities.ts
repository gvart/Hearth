// Typed client and hooks for a device's capabilities (#346):
// GET and PUT /api/v1/devices/{id}/capabilities. Raising a terminal, exec,
// restart or Docker control asks for the password again (reauth.ts).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { applied, raisesRisky, type Capabilities } from '../capabilities.ts';
import { request, type Ceiling } from './client.ts';
import { keys as appKeys } from './hooks.ts';
import { useWithReauth } from './reauth.ts';

const path = (id: string) => `/devices/${encodeURIComponent(id)}/capabilities`;

const capsKey = (id: string) => ['devices', id, 'capabilities'] as const;

/** The device's capabilities; polled often while the agent has not applied the last change. */
export function useCapabilities(id: string) {
  return useQuery({
    queryKey: capsKey(id),
    queryFn: () => request<Capabilities>('GET', path(id)),
    refetchInterval: (q) => (q.state.data && !applied(q.state.data) ? 2000 : 15000),
  });
}

/** Sets what the hub sets for the device, the whole of it: with the password again when it raises a risky one. */
export function useSetCapabilities(id: string) {
  const qc = useQueryClient();
  const withReauth = useWithReauth();
  return useMutation({
    mutationFn: (req: { from: Ceiling; to: Ceiling }) => {
      const put = () => request<Capabilities>('PUT', path(id), { hub: req.to });
      return raisesRisky(req.from, req.to) ? withReauth(put) : put();
    },
    onSuccess: (caps) => {
      qc.setQueryData(capsKey(id), caps);
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: capsKey(id) });
      void qc.invalidateQueries({ queryKey: appKeys.devices });
    },
  });
}
