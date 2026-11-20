import { CustodyClient } from '../../shared/client';
import { ConnectionClient } from '../../shared/connection-client';
import { RemoteFlowStore } from '../../shared/operation-continuations';
import { OperationClient } from '../../shared/operation-client';
import { api, ApiFailure, session } from './api';
import { getIdentity } from './keys';

export async function custodyClient(principalId?: string) {
  const id = principalId ?? (await session()).principal?.id;
  if (!id) throw new ApiFailure('unauthenticated');
  const identity = await getIdentity(id);
  if (!identity) throw new ApiFailure('key_locked');
  return new CustodyClient({ json: (path, options, schema) => api(path.slice(4), options, schema) },
    location.origin, id, { publicKey: identity.publicKey, privateKey: identity.privateKey });
}
export async function connectionClient() {
  const custody = await custodyClient();
  return new ConnectionClient(custody, new RemoteFlowStore(custody));
}
export async function operationClient() {
  const connections = await connectionClient();
  return new OperationClient(connections.custody, connections);
}
