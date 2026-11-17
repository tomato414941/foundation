import { enroll, fixture } from './support.js';
import { Bindings } from '../server/bindings.js';
import { Custody } from '../server/custody.js';
import { newIdentityKeys } from '../shared/authority.js';
import { AccessPolicy, ContentTypes, protect } from '../shared/custody.js';
import { encode } from '../shared/encryption.js';
import type { Journal } from '../runtime/journal.js';

export class MemoryJournal implements Journal {
  entries = new Map<string, unknown>();
  async read<T>(id: string): Promise<T | null> { return structuredClone(this.entries.get(id) ?? null) as T | null; }
  async write(id: string, value: unknown) { this.entries.set(id, structuredClone(value)); }
  async keys(prefix: string) { return [...this.entries.keys()].filter(key => key.startsWith(prefix)); }
  async pending(prefix: string) {
    return (await this.keys(prefix)).filter(key => (this.entries.get(key) as { delivered?: boolean } | undefined)?.delivered !== true);
  }
}

export async function delegatedFixture() {
  const f = await fixture();
  const bindings = new Bindings(f.db, f.authorization, f.audit, f.confirmations);
  const custody = new Custody(f.resources, bindings, f.relations, f.config.origin);
  async function person(name: string) {
    const keys = await newIdentityKeys();
    const { binding, ...enrolled } = await enroll(f.authentication, name, keys);
    const actor = (await f.authentication.authenticate(enrolled.token))!;
    return { keys, binding, actor, token: enrolled.token };
  }
  // The delegate acts for the owner, so the owner's items are sealed to it as well.
  const owner = await person('Owner'), delegate = await person('Delegate'), stranger = await person('Other');
  await f.relations.draw(owner.actor, { subjectId: delegate.actor.id, relation: 'delegate', objectId: owner.actor.id });
  const policy = AccessPolicy.parse({
    format: 2, id: crypto.randomUUID(), origin: f.config.origin, ownerId: owner.actor.id,
    contentType: ContentTypes.value, revision: 1, authorities: [owner.binding, delegate.binding], readers: [owner.binding, delegate.binding],
    grants: [],
  });
  const content = await protect(encode('confidential-value'), policy, 1, owner.binding, owner.keys);
  const resource = await custody.put(owner.actor, { name: 'Credential', content, data: { bytes: 18 } });
  return { ...f, bindings, custody, owner, delegate, stranger, policy, content, resource, personWithKeys: person };
}
