import { fixture } from './support.js';
import { Bindings } from '../server/bindings.js';
import { Custody } from '../server/custody.js';
import { Delegation } from '../server/delegation.js';
import { bindKeys, hash, newIdentityKeys, publicPart, signBinding } from '../shared/authority.js';
import { AccessPolicy, ContentTypes, Operations, prepareRun, protect } from '../shared/custody.js';
import type { ExecutionIntent } from '../shared/custody.js';
import { signEnvironment } from '../shared/execution.js';
import { encode } from '../shared/encryption.js';
import type { Journal } from '../runtime/journal.js';
import type { ExecutionBroker } from '../runtime/executor.js';

export class MemoryJournal implements Journal {
  entries = new Map<string, unknown>();
  async read<T>(id: string): Promise<T | null> { return structuredClone(this.entries.get(id) ?? null) as T | null; }
  async write(id: string, value: unknown) { this.entries.set(id, structuredClone(value)); }
  async keys(prefix: string) { return [...this.entries.keys()].filter(key => key.startsWith(prefix)); }
}

export async function delegatedFixture() {
  const f = await fixture();
  const bindings = new Bindings(f.db, f.authorization, f.audit);
  const custody = new Custody(f.resources, bindings, f.relations, f.config.origin);
  const delegation = new Delegation(f.resources, bindings, custody, f.config.origin);
  async function person(name: string) {
    const keys = await newIdentityKeys();
    const enrolled = await f.authentication.enroll(name, publicPart(keys.encryption));
    const actor = (await f.authentication.authenticate(enrolled.token))!;
    const binding = bindKeys(actor.id, keys);
    await bindings.publish(actor, await signBinding(binding, keys));
    return { keys, binding, actor, token: enrolled.token };
  }
  const owner = await person('Owner'), executor = await person('Executor'), stranger = await person('Other');
  await f.relations.draw(owner.actor, { subjectId: executor.actor.id, relation: 'agent', objectId: owner.actor.id });
  const environment = await signEnvironment({
    format: 3, id: crypto.randomUUID(), origin: f.config.origin, ownerId: owner.actor.id,
    name: 'Own server', executor: executor.binding, operatorId: executor.actor.id,
    driver: 'attached', capabilities: Object.values(Operations),
    isolation: 'process', revision: 1,
  }, executor.keys);
  await delegation.register(executor.actor, environment);
  const policy = AccessPolicy.parse({
    format: 2, id: crypto.randomUUID(), origin: f.config.origin, ownerId: owner.actor.id,
    contentType: ContentTypes.value, revision: 1, authorities: [owner.binding], readers: [owner.binding],
    grants: [{ actor: owner.binding, executor: executor.binding,
      operations: [Operations.http, Operations.command], callerProgram: true,
      expiresAt: new Date(Date.now() + 3_600_000).toISOString() }],
  });
  const content = await protect(encode('confidential-value'), policy, 1, owner.binding, owner.keys);
  const resource = await custody.put(owner.actor, { name: 'Credential', content, data: { bytes: 18 } });
  const operation = { kind: 'http', request: { url: 'https://service.example/items',
    method: 'POST', body: 'private-request-body' } };
  const intent: ExecutionIntent = {
    format: 2, id: crypto.randomUUID(), origin: f.config.origin, ownerId: owner.actor.id,
    actor: owner.binding, environmentId: environment.manifest.id, executor: executor.binding,
    environmentDigest: await hash(environment.manifest),
    operation: Operations.http, functionDigest: null, operationDigest: await hash(operation),
    sources: [{ id: policy.id, materialRevision: 1, policyDigest: await hash(policy) }],
    resultRecipients: [owner.binding], createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
  };
  const request = await prepareRun(intent, operation, owner.keys);
  const broker: ExecutionBroker = {
    claim: id => delegation.claim(executor.actor, id),
    renew: (id, lease) => delegation.renew(executor.actor, id, lease),
    dispatch: (id, lease) => delegation.dispatch(executor.actor, id, lease),
    finish: (lease, receipt) => delegation.finish(executor.actor, lease, receipt),
    capture: (name, content) => custody.putProduced(executor.actor, { name, content }),
  };
  return { ...f, bindings, custody, delegation, owner, executor, stranger, environment, policy, content,
    resource, intent, request, operation, broker, personWithKeys: person };
}
