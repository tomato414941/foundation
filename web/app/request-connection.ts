import type { DefinitionCall } from '../../shared/executions';
import { CatalogMethod, Principal, Resource, listOf } from '../../shared/contracts';
import { api, ApiFailure } from './api';

export async function requestConnectionMethod(id: string, signal?: AbortSignal) {
  const methods = await api('/connection-methods', { signal }, listOf(CatalogMethod));
  const method = methods.items.find(item => item.id === id);
  if (!method) throw new ApiFailure('operation_unavailable');
  return method;
}

export async function loadRequestConnection(invocation: DefinitionCall, signal?: AbortSignal, inspect = true) {
  const { input } = invocation;
  const name = typeof input.name === 'string' ? input.name : '';
  const reconnecting = typeof input.connectionId === 'string';
  if (!inspect) return { method: null, users: [], usersConfigured: false, name, reconnecting };
  const [method, connection, users] = await Promise.all([
    requestConnectionMethod(String(input.methodId), signal),
    typeof input.connectionId === 'string' ? api('/resources/' + input.connectionId, { signal }, Resource) : null,
    Promise.all((Array.isArray(input.users) ? input.users : []).map(id =>
      api('/identities/' + String(id), { signal }, Principal.pick({ id: true, name: true, publicKey: true })))),
  ]);
  return { method, users, usersConfigured: Array.isArray(input.users),
    name: connection?.name ?? (name || method.defaultName), reconnecting };
}
