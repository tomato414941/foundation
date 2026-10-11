import { z } from 'zod';
import { Id, Sealed } from './contracts.js';
import { Signature, canonical, sign, verify } from './authority.js';
import { decode, encode, open, seal } from './encryption.js';
import { FlowRecord } from './connection-client.js';
import type { ConnectionFlow, FlowStore } from './connection-client.js';
import type { CustodyClient } from './client.js';

export const ContinuationEnvelope = z.object({ id: Id, actorId: Id, bindingId: Id, origin: z.url(),
  revision: z.number().int().positive(), sealed: Sealed, signature: Signature }).strict();
export const continuationContext = (origin: string, id: string) => 'operation-continuation:' + origin + ':' + id;

// The server stores only sealed, signed progress. Any device with the initiating identity's keys can resume it.
export class SealedContinuationStore {
  private readonly revisions = new Map<string, number>();
  constructor(readonly custody: CustodyClient) {}
  async get<T>(id: string, schema: z.ZodType<T>): Promise<T | null> {
    const envelope = await this.custody.api.json('/api/operation-continuations/' + Id.parse(id), {}, ContinuationEnvelope.nullable());
    if (!envelope) { this.revisions.set(id, 0); return null; }
    const { signature, ...value } = envelope;
    if (value.id !== id || value.origin !== this.custody.origin || value.actorId !== this.custody.binding.principalId ||
      value.bindingId !== this.custody.binding.id) throw new Error('Use the identity that started this operation.');
    await verify(value, signature, this.custody.binding.signing, 'operation-continuation');
    const record = schema.parse(JSON.parse(decode(await open(value.sealed, this.custody.keys.encryption,
      this.custody.binding.id, continuationContext(this.custody.origin, id)))));
    this.revisions.set(id, value.revision);
    return record;
  }
  async put(id: string, record: unknown) {
    if (!this.revisions.has(id)) await this.get(id, z.unknown());
    const value = { id, origin: this.custody.origin, actorId: this.custody.binding.principalId,
      bindingId: this.custody.binding.id, revision: this.revisions.get(id)! + 1,
      sealed: await seal(encode(canonical(record)), [{ id: this.custody.binding.id,
        publicKey: this.custody.binding.encryption }], continuationContext(this.custody.origin, id)) };
    const signature = await sign(value, this.custody.keys.signing, 'operation-continuation');
    await this.custody.api.json('/api/operation-continuations/' + id, { method: 'PUT', body: { ...value, signature } }, ContinuationEnvelope);
    this.revisions.set(id, value.revision);
  }
}
export class RemoteFlowStore implements FlowStore {
  readonly records: SealedContinuationStore;
  constructor(custody: CustodyClient) { this.records = new SealedContinuationStore(custody); }
  async get(id: string): Promise<ConnectionFlow | null> {
    const flow = await this.records.get(id, FlowRecord);
    if (flow && flow.id !== id) throw new Error('The saved progress belongs to another operation.');
    return flow;
  }
  put(flow: ConnectionFlow) { return this.records.put(flow.id, FlowRecord.parse(flow)); }
}
