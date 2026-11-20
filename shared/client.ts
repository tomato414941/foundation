import { z } from 'zod';
import type { JWK } from 'jose';
import { RequestView } from './operations.js';
import { CatalogMethod, Id, Recipient, Resource, listOf } from './contracts.js';
import type { JsonValue, PublicEncryptionKey, ResourceView } from './contracts.js';
import { catalogDefinition } from './connection-methods.js';
import { openConnection } from './connections.js';
import type { ConnectionLabels } from './connections.js';
import { openItem, sealItem, sealedFor } from './custody.js';
import type { SealedItemValue } from './custody.js';
import { KeySharingItem, ProtectedRead, Reprotection } from './protocol.js';
import type { ProtectedWrite } from './protocol.js';
import { isProtected } from './protected.js';
import type { ProtectedKindName } from './protected.js';

export interface JsonApi {
  json<T = unknown>(path: string, options?: { method?: string; body?: unknown; signal?: AbortSignal }, schema?: z.ZodType<T>): Promise<T>;
}
export class ClientFailure extends Error {
  constructor(readonly code: string, message: string) { super(message); }
}
// The key this device opens what is sealed for its principal with.
export interface DeviceKeys { publicKey: PublicEncryptionKey; privateKey: JWK | CryptoKey }
// Where a value is saved: an item there is, or a new one of the owner's.
export interface ItemTarget { id: string; ownerId: string; kind: ProtectedKindName }
type Saved = { kind: ProtectedKindName; content: SealedItemValue; version: number };
const errorIs = (error: unknown, ...codes: Array<string | number>) => !!error && typeof error === 'object' &&
  (('code' in error && codes.includes(String(error.code))) || ('status' in error && codes.includes(Number(error.status))));
// Items without sealed content use the same transfer operation without opening this device's private key.
export async function transferResource(api: JsonApi, id: string, to: string, open: () => CustodyClient | Promise<CustodyClient>) {
  Id.parse(to);
  const resource = await api.json('/api/resources/' + Id.parse(id), {}, Resource);
  if (isProtected(resource.kind)) return (await open()).transferProtected(resource, to);
  return api.json('/api/resources/' + id + '/transfer', { method: 'POST', body: { to, version: resource.version } },
    z.union([Resource, RequestView]));
}
// Opens and seals what its principal keeps. Foundation decides who may open an item: the device seals each value for
// everyone it lists, each by the key it has now.
export class CustodyClient {
  constructor(readonly api: JsonApi, readonly origin: string, readonly principalId: string, readonly keys: DeviceKeys) {}

  // The item as sealed, and whether it is sealed for this device's key.
  async latest(id: string): Promise<Saved & { opens: boolean }> {
    const item = await this.api.json('/api/resources/' + Id.parse(id) + '/custody', {}, ProtectedRead);
    return { ...item, opens: await sealedFor(item.content, this.keys.publicKey) };
  }
  async read(id: string): Promise<Saved> {
    const { opens, ...item } = await this.latest(id);
    if (!opens) throw new ClientFailure('not_sealed_for_key', 'This item is not sealed for the current key of this identity yet. ' +
      'Ask someone who can open it to seal it again, or enter its value again.');
    return item;
  }
  open(content: SealedItemValue) {
    return openItem(content, this.keys.privateKey, this.keys.publicKey);
  }
  async reveal(id: string) {
    return this.open((await this.read(id)).content);
  }
  // A connection as its holder reads it to change it: what is sealed of it, with its method as the method now is.
  async connection(id: string) {
    const { content } = await this.read(id), bytes = await this.open(content);
    const method = catalogDefinition(await this.api.json('/api/connections/' + Id.parse(id) + '/method', {}, CatalogMethod));
    return openConnection(bytes, content.metadata, method);
  }
  // Everyone a value is sealed for: who may open the item, or a new item of the owner's.
  async recipients(target: ItemTarget, existing: boolean) {
    return (await this.api.json(existing ? '/api/resources/' + Id.parse(target.id) + '/recipients'
      : '/api/principals/' + Id.parse(target.ownerId) + '/recipients', {}, listOf(Recipient))).items;
  }
  // Seals a value of an item there is for everyone who may open it now.
  async seal(id: string, bytes: Uint8Array, revision: number, metadata: Record<string, JsonValue>) {
    const recipients = (await this.api.json('/api/resources/' + Id.parse(id) + '/recipients', {}, listOf(Recipient))).items;
    return sealItem(bytes, recipients, revision, metadata);
  }
  // Seals the value for everyone who may open the item and saves it: a new item, or the next revision of one there is.
  async save(target: ItemTarget, name: string, bytes: Uint8Array, options: { metadata?: Record<string, JsonValue>;
    labels?: z.infer<typeof ConnectionLabels>; previous?: Saved;
    commit?: (write: z.infer<typeof ProtectedWrite>) => Promise<ResourceView> } = {}) {
    const { previous } = options;
    const metadata = options.metadata ?? (target.kind === 'variable' ? { bytes: bytes.byteLength } : {});
    for (let attempt = 1; ; attempt++) {
      const content = await sealItem(bytes, await this.recipients(target, !!previous), (previous?.content.revision ?? 0) + 1, metadata);
      const write = { id: target.id, name, kind: target.kind, ownerId: target.ownerId, content,
        ...(options.labels ? { labels: options.labels } : {}), ...(previous ? { version: previous.version } : {}) };
      try {
        return options.commit ? await options.commit(write)
          : await this.api.json('/api/resources/' + Id.parse(target.id) + '/custody', { method: 'PUT', body: write }, Resource);
      } catch (error) {
        // Someone was let in or out while it was sealed: it is sealed again for those who may open it now.
        if (attempt < 3 && errorIs(error, 'recipients_changed')) continue;
        throw error;
      }
    }
  }
  // Passes the item on, sealed for whoever uses what the new owner holds. Foundation keeps its current owner and content
  // until the new owner accepts it.
  async transferProtected(resource: ResourceView, to: string) {
    const path = '/api/resources/' + resource.id + '/transfer';
    const previous = await this.read(resource.id);
    if (previous.version !== resource.version)
      throw new ClientFailure('changed', 'This item changed. Reload it before transferring it.');
    const bytes = await this.open(previous.content);
    for (let attempt = 1; ; attempt++) {
      const recipients = (await this.api.json(path + '-recipients?to=' + encodeURIComponent(to), {}, listOf(Recipient))).items;
      const content = await sealItem(bytes, recipients, previous.content.revision + 1, previous.content.metadata);
      try {
        return await this.api.json(path, { method: 'POST', body: { to, content, version: previous.version } },
          z.union([Resource, RequestView]));
      } catch (error) {
        if (attempt < 3 && errorIs(error, 'recipients_changed')) continue;
        throw error;
      }
    }
  }
  // Seals each item for whoever may open it once a change is made, as Foundation lists them, for the change to carry.
  async sharing(input: string | Array<z.infer<typeof KeySharingItem>>) {
    const items = typeof input === 'string' ? (await this.api.json(input, {}, listOf(KeySharingItem))).items : input;
    const updates: Record<string, { version: number; content: SealedItemValue }> = {};
    for (const item of items) {
      const current = await this.read(item.id);
      if (current.version !== item.version)
        throw new ClientFailure('changed', 'This item changed. Reload it before changing who opens it.');
      updates[item.id] = { version: item.version, content: await sealItem(await this.open(current.content), item.recipients,
        current.content.revision + 1, current.content.metadata) };
    }
    return updates;
  }
  // Items someone may open that are not sealed for them yet, which this device can seal again.
  async pendingProtection() {
    return (await this.api.json('/api/principals/' + this.principalId + '/reprotection', {}, listOf(Reprotection))).items;
  }
  // Seals the item again for everyone who may open it now.
  async reprotect(id: string) {
    const previous = await this.read(id);
    const resource = await this.api.json('/api/resources/' + Id.parse(id), {}, Resource);
    if (!isProtected(resource.kind)) throw new ClientFailure('wrong_kind', 'Only sealed items are sealed again.');
    return this.save({ id, ownerId: resource.ownerId, kind: resource.kind }, resource.name, await this.open(previous.content),
      { metadata: previous.content.metadata, previous });
  }
  // Seals each listed item again on its own: one that cannot change now is left, with the reason, for another time.
  async reprotectPending(onProgress?: (progress: { completed: number; total: number }) => void) {
    const done: string[] = [], failed: Array<{ id: string; code: string }> = [];
    const items = await this.pendingProtection();
    let completed = 0;
    onProgress?.({ completed, total: items.length });
    for (const item of items) {
      try {
        await this.reprotect(item.id);
        done.push(item.id);
      } catch (error) {
        failed.push({ id: item.id, code: error && typeof error === 'object' && 'code' in error && typeof error.code === 'string'
          ? error.code : 'failure' });
      }
      onProgress?.({ completed: ++completed, total: items.length });
    }
    return { done, failed };
  }
  // The items to open for a command, with the application each connection was made with.
  async sourceContents(ids: string[]) {
    const sources = new Map<string, Saved & { kind: ProtectedKindName }>();
    for (const id of new Set(ids)) sources.set(id, await this.read(id));
    for (const source of [...sources.values()]) {
      const appId = source.content.metadata.appId;
      if (typeof appId === 'string' && !sources.has(appId)) sources.set(appId, await this.read(appId));
    }
    return sources;
  }
}
