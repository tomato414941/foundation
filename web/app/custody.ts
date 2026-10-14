import { CustodyClient } from '../../shared/client';
import type { TrustStore } from '../../shared/client';
import { canonical, hash, sign, validateBinding, verify } from '../../shared/authority';
import type { BoundKeys, KeyMaterial } from '../../shared/authority';
import type { CustodyContent, CustodyPolicy, SealedRun } from '../../shared/custody';
import { ConnectionClient } from '../../shared/connection-client';
import { RemoteFlowStore } from '../../shared/operation-continuations';
import { ExecutionClient } from '../../shared/execution-client';
import { FunctionClient } from '../../shared/function-client';
import { api, ApiFailure, session } from './api';
import { getIdentity } from './keys';
import { stored } from './storage';

class BrowserTrust implements TrustStore {
  constructor(readonly bindingKeys: BoundKeys, readonly keys: KeyMaterial) {}
  private context(id: string) { return { origin: location.origin, binding: this.bindingKeys.id, id }; }
  private key(id: string) { return this.bindingKeys.id + ':' + id; }
  async get<T>(id: string): Promise<T | null> {
    const record = await stored('records', 'readonly', store => store.get(this.key(id))) as
      { value: T; signature: string } | undefined;
    if (!record) return null;
    await verify({ ...this.context(id), value: record.value }, record.signature, this.bindingKeys.signing, 'browser-record');
    return record.value;
  }
  async put(id: string, value: unknown) {
    const signature = await sign({ ...this.context(id), value }, this.keys.signing, 'browser-record');
    await stored('records', 'readwrite', store => store.put({ value, signature }, this.key(id)));
  }
  binding(id: string) { return this.get<BoundKeys>('identity:' + id); }
  async bindings() {
    const prefix = this.key('identity:'), keys = await stored('records', 'readonly',
      store => store.getAllKeys(IDBKeyRange.bound(prefix, prefix + '\uffff')));
    const bindings = await Promise.all(keys.map(key => this.get<BoundKeys>(String(key).slice(this.key('').length))));
    return bindings.filter(binding => binding !== null);
  }
  async rememberBinding(binding: BoundKeys) { await validateBinding(binding); await this.put('identity:' + binding.principalId, binding); }
  keyring() { return this.get<{ revision: number; digest: string }>('keyring'); }
  async rememberKeyring(seen: { revision: number; digest: string }) { await this.put('keyring', seen); }
  checkpoint(content: CustodyContent) {
    return this.get<{ policy: CustodyPolicy; materialRevision: number; digest: string }>(
      'checkpoint:' + content.policy.format + ':' + content.policy.id);
  }
  async rememberContent(content: CustodyContent) {
    await this.put('checkpoint:' + content.policy.format + ':' + content.policy.id, {
      policy: content.policy, materialRevision: content.materialRevision, digest: await hash(content),
    });
  }
  run(id: string) { return this.get<SealedRun>('run:' + id); }
  async rememberRun(request: SealedRun) {
    const previous = await this.run(request.intent.id);
    if (previous && canonical(previous) !== canonical(request)) throw new ApiFailure('execution_changed');
    await this.put('run:' + request.intent.id, request);
  }
}
export async function custodyClient(principalId?: string) {
  const id = principalId ?? (await session()).principal?.id;
  if (!id) throw new ApiFailure('unauthenticated');
  const identity = await getIdentity(id);
  if (!identity) throw new ApiFailure('key_locked');
  const trust = new BrowserTrust(identity.binding, identity.keys);
  return new CustodyClient({ json: (path, options, schema) => api(path.slice(4), options, schema) },
    location.origin, identity.binding, identity.keys, trust);
}
export async function connectionClient() {
  const custody = await custodyClient();
  return new ConnectionClient(custody, new RemoteFlowStore(custody));
}
export async function executionClient() {
  const connections = await connectionClient();
  return new ExecutionClient(connections.custody, connections);
}
export async function functionClient(withKeys = false) {
  return new FunctionClient({ json: (path, options, schema) => api(path.slice(4), options, schema) },
    withKeys ? await custodyClient() : undefined);
}
