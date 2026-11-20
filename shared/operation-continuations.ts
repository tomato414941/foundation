import { z } from 'zod';
import { Id, Sealed } from './contracts.js';
import { canonical } from './digest.js';
import { decode, encode, open, seal, thumbprint } from './encryption.js';
import { FlowRecord } from './connection-client.js';
import type { ConnectionFlow, FlowStore } from './connection-client.js';
import type { CustodyClient } from './client.js';

export const ContinuationEnvelope = z.object({ id: Id, actorId: Id, origin: z.url(),
  revision: z.number().int().positive(), sealed: Sealed }).strict();
export const continuationContext = (origin: string, id: string) => 'operation-continuation:' + origin + ':' + id;

// The server stores only progress sealed for the initiating identity's key. Any device with that key can resume it.
export class SealedContinuationStore {
  private readonly revisions = new Map<string, number>();
  constructor(readonly custody: CustodyClient) {}
  get origin() { return this.custody.origin; }
  async get<T>(id: string, schema: z.ZodType<T>): Promise<T | null> {
    const envelope = await this.custody.api.json('/api/operation-continuations/' + Id.parse(id), {}, ContinuationEnvelope.nullable());
    if (!envelope) { this.revisions.set(id, 0); return null; }
    if (envelope.id !== id || envelope.origin !== this.origin || envelope.actorId !== this.custody.principalId)
      throw new Error('Use the identity that started this operation.');
    const record = schema.parse(JSON.parse(decode(await open(envelope.sealed, this.custody.keys.privateKey,
      await thumbprint(this.custody.keys.publicKey), continuationContext(this.origin, id)))));
    this.revisions.set(id, envelope.revision);
    return record;
  }
  async put(id: string, record: unknown) {
    if (!this.revisions.has(id)) await this.get(id, z.unknown());
    const value = { id, origin: this.origin, actorId: this.custody.principalId, revision: this.revisions.get(id)! + 1,
      sealed: await seal(encode(canonical(record)), [{ id: await thumbprint(this.custody.keys.publicKey),
        publicKey: this.custody.keys.publicKey }], continuationContext(this.origin, id)) };
    await this.custody.api.json('/api/operation-continuations/' + id, { method: 'PUT', body: value }, ContinuationEnvelope);
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
