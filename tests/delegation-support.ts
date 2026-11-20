import { enroll, fixture } from './support.js';
import { newIdentityKeys, publicPart } from '../shared/encryption.js';
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
  async function person(name: string) {
    const identityKeys = await newIdentityKeys();
    const keys = { ...identityKeys, publicKey: publicPart(identityKeys.encryption), privateKey: identityKeys.encryption };
    const enrolled = await enroll(f.authentication, name, identityKeys);
    const actor = (await f.authentication.authenticate(enrolled.token))!;
    return { keys, actor, token: enrolled.token };
  }
  // The delegate acts for the owner, so the owner's items are sealed for it as well.
  const owner = await person('Owner'), delegate = await person('Delegate'), stranger = await person('Other');
  await f.relations.draw(owner.actor, { subjectId: delegate.actor.id, relation: 'delegate', objectId: owner.actor.id });
  const resource = await f.keep(owner.actor, owner.actor.id, 'Credential', 'confidential-value');
  return { ...f, owner, delegate, stranger, resource, personWithKeys: person };
}
