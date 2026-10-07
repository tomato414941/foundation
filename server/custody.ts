import type { Actor } from './authorization.js';
import type { Queryable } from './database.js';
import type { Resources, ResourceRow } from './resources.js';
import type { Bindings } from './bindings.js';
import { canonical, hash } from '../shared/authority.js';
import type { BoundKeys } from '../shared/authority.js';
import { ProtectedContent, ProtectedKind, verifyContent } from '../shared/custody.js';
import type { CustodyContent } from '../shared/custody.js';
import type { JsonValue } from '../shared/contracts.js';
import { fail } from './errors.js';

export interface ProtectedWrite {
  name: string;
  content: CustodyContent;
  data?: Record<string, JsonValue>;
  version?: number;
}

export class Custody {
  constructor(readonly resources: Resources, readonly bindings: Bindings, readonly origin: string) {}

  async get(id: string, connection: Queryable = this.resources.db.pool): Promise<CustodyContent> {
    const row = await this.resources.db.one<{ content: CustodyContent }>(
      'SELECT content FROM resource_custody WHERE resource_id=$1', [id], connection,
    );
    if (!row) fail(409, 'custody_required', 'Encrypt this item for its readers and execution environments.');
    return ProtectedContent.parse(row.content);
  }

  async recipients(ownerId: string, connection: Queryable = this.resources.db.pool) {
    const principals = await this.resources.recipients(ownerId, connection);
    return Promise.all(principals.map(async principal => ({
      name: principal.name, ...(await this.bindings.current(principal.id, connection)),
    })));
  }

  async read(actor: Actor, id: string) {
    await this.resources.authorization.active(actor);
    const row = await this.resources.get(id);
    const content = await this.get(id);
    const { binding } = await this.bindings.current(actor.id);
    if (!content.policy.readers.some(reader => canonical(reader) === canonical(binding)) &&
      !content.policy.grants.some(grant => (canonical(grant.executor) === canonical(binding) ||
        canonical(grant.actor) === canonical(binding)) &&
        Date.parse(grant.expiresAt) > Date.now()))
      fail(403, 'forbidden', 'This identity is not a recipient of this item.');
    await this.resources.authorization.requireResource(actor, row, 'read');
    return { content, version: row.version };
  }

  async put(actor: Actor, input: ProtectedWrite) {
    const content = await verifyContent(input.content), policy = content.policy;
    if (input.data && canonical(input.data) !== canonical(content.metadata))
      fail(400, 'invalid_metadata', 'Sign the public metadata together with its encrypted content.');
    if (policy.origin !== this.origin) fail(400, 'wrong_origin', 'This content belongs to another Foundation server.');
    const { binding } = await this.bindings.current(actor.id);
    if (content.signerId !== binding.id || !policy.authorities.some(authority => canonical(authority) === canonical(binding)))
      fail(403, 'forbidden', 'Sign this change as an authorized editor of the item.');
    const allBindings = [...policy.readers, ...policy.authorities,
      ...policy.grants.flatMap(grant => [grant.actor, grant.executor])];
    for (const keys of new Map(allBindings.map(keys => [keys.id, keys])).values())
      await this.bindings.requireCurrent(keys);
    return this.resources.db.transaction(async connection => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      const current = await this.resources.db.one<ResourceRow>(
        'SELECT * FROM resources WHERE id=$1 FOR UPDATE', [policy.id], connection,
      );
      if (current) {
        if (current.owner_id !== policy.ownerId || current.kind !== policy.kind)
          fail(400, 'wrong_resource', 'Keep the same owner and resource kind when updating an item.');
        await this.resources.authorization.requireResource(actor, current, 'update', connection);
        if (current.version !== input.version) fail(409, 'changed', 'This item changed. Reload it before saving.');
        const previous = await this.resources.db.one<{ content: CustodyContent }>(
          'SELECT content FROM resource_custody WHERE resource_id=$1', [policy.id], connection,
        );
        if (previous) {
          if (!previous.content.policy.authorities.some(authority => canonical(authority) === canonical(binding)))
            fail(403, 'forbidden', 'The existing policy must authorize its editor.');
          const policyChanged = await hash(previous.content.policy) !== await hash(policy);
          if (policy.revision !== previous.content.policy.revision + (policyChanged ? 1 : 0) ||
            content.materialRevision !== previous.content.materialRevision + 1)
            fail(409, 'changed', 'Advance the current content and policy revisions.');
          const pending = await this.resources.db.one(
            "SELECT 1 FROM connection_operations WHERE resource_id=$1 AND state IN ('prepared','in_flight','uncertain')",
            [policy.id], connection,
          );
          if (pending) fail(409, 'connection_busy', 'Resolve the current connection update before editing its recipients.');
        } else {
          await this.resources.authorization.requireResource(actor, current, 'reveal', connection);
          if (policy.revision !== 1 || content.materialRevision !== 1)
            fail(400, 'invalid_revision', 'Begin encrypted custody at revision one.');
        }
      } else {
        if (!(await this.resources.authorization.canCreate(actor, policy.ownerId, policy.kind, connection)))
          fail(403, 'forbidden', 'You cannot create this item for this principal.');
        if (policy.revision !== 1 || content.materialRevision !== 1)
          fail(400, 'invalid_revision', 'Begin encrypted custody at revision one.');
      }
      for (const recipient of await this.recipients(policy.ownerId, connection)) {
        if (!policy.readers.some(reader => canonical(reader) === canonical(recipient.binding)))
          fail(400, 'missing_recipient', 'Include every owner and member as an encrypted recipient.');
      }
      const data = { ...content.metadata, recipients: policy.readers.map(reader => reader.principalId),
        executors: [...new Set(policy.grants.map(grant => grant.executor.principalId))],
        custodyRevision: policy.revision };
      let row: ResourceRow;
      if (current) {
        row = await this.resources.update(current, { name: input.name, data }, connection);
        await connection.query('UPDATE resources SET private_data=NULL,sealed=NULL WHERE id=$1', [policy.id]);
        row = { ...row, private_data: null, sealed: null };
      } else row = await this.resources.insert(policy.ownerId, ProtectedKind.parse(policy.kind), input.name,
        data, { id: policy.id }, connection);
      await connection.query(
        'INSERT INTO resource_custody(resource_id,content) VALUES($1,$2) ON CONFLICT(resource_id) DO UPDATE SET content=EXCLUDED.content',
        [policy.id, JSON.stringify(content)],
      );
      await this.projectGrants(content, connection);
      await this.resources.audit.record(policy.ownerId, actor.id, 'resource.protect', policy.id,
        { policyRevision: policy.revision, materialRevision: content.materialRevision }, connection);
      return row;
    });
  }

  async putProduced(actor: Actor, input: ProtectedWrite) {
    const content = await verifyContent(input.content), policy = content.policy;
    const { binding } = await this.bindings.current(actor.id);
    if (policy.origin !== this.origin || content.signerId !== binding.id || !content.creationRunId)
      fail(403, 'forbidden', 'Store output from an execution approved for this identity.');
    const producer = policy.producers.find(producer => producer.runId === content.creationRunId &&
      producer.materialRevision === content.materialRevision && canonical(producer.executor) === canonical(binding) &&
      Date.parse(producer.expiresAt) > Date.now());
    if (!producer) fail(403, 'forbidden', 'Approve this execution before saving its output.');
    const authority = policy.authorities.find(authority => authority.id === content.authorityId)!;
    await this.bindings.requireCurrent(authority);
    const task = await this.resources.db.one<{ request: { intent: { actor: BoundKeys; ownerId: string; executor: BoundKeys } } }>(
      "SELECT request FROM execution_tasks WHERE id=$1 AND phase='dispatched' AND state IN ('running','uncertain')",
      [content.creationRunId],
    );
    if (!task || task.request.intent.ownerId !== policy.ownerId ||
      canonical(task.request.intent.actor) !== canonical(authority) ||
      canonical(task.request.intent.executor) !== canonical(binding))
      fail(403, 'forbidden', 'Use the output destination approved by this execution requester.');
    return this.resources.db.transaction(async connection => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      const current = await this.resources.db.one<ResourceRow>('SELECT * FROM resources WHERE id=$1 FOR UPDATE', [policy.id], connection);
      if (current) {
        const previous = await this.get(policy.id, connection);
        if (canonical(previous) === canonical(content)) return current;
        await this.resources.authorization.requireResource({ id: authority.principalId }, current, 'update', connection);
        if (current.owner_id !== policy.ownerId || current.kind !== policy.kind ||
          !previous.policy.authorities.some(value => canonical(value) === canonical(authority)) ||
          content.materialRevision !== previous.materialRevision + 1 ||
          policy.revision !== previous.policy.revision + (await hash(policy) === await hash(previous.policy) ? 0 : 1))
          fail(409, 'changed', 'Review the current output destination before replacing it.');
        const pending = await this.resources.db.one(
          "SELECT 1 FROM connection_operations WHERE resource_id=$1 AND state IN ('prepared','in_flight','uncertain')",
          [policy.id], connection,
        );
        if (pending) fail(409, 'connection_busy', 'Resolve the current connection update before replacing it.');
      } else {
        if (content.materialRevision !== 1 || policy.revision !== 1)
          fail(400, 'invalid_revision', 'Start a new output at revision one.');
        if (!(await this.resources.authorization.canCreate({ id: authority.principalId }, policy.ownerId, policy.kind, connection)))
          fail(403, 'forbidden', 'The execution requester cannot create this output.');
      }
      for (const recipient of await this.recipients(policy.ownerId, connection))
        if (!policy.readers.some(reader => canonical(reader) === canonical(recipient.binding)))
          fail(400, 'missing_recipient', 'Include every owner and member as an encrypted recipient.');
      const data = { ...content.metadata, recipients: policy.readers.map(reader => reader.principalId),
        executors: [...new Set(policy.grants.map(grant => grant.executor.principalId))], custodyRevision: policy.revision };
      const row = current
        ? await this.resources.update(current, { name: input.name, data }, connection)
        : await this.resources.insert(policy.ownerId, policy.kind, input.name, data, { id: policy.id }, connection);
      await connection.query(
        'INSERT INTO resource_custody(resource_id,content) VALUES($1,$2) ON CONFLICT(resource_id) DO UPDATE SET content=EXCLUDED.content',
        [policy.id, JSON.stringify(content)],
      );
      await this.projectGrants(content, connection);
      await this.resources.audit.record(policy.ownerId, actor.id, 'resource.capture', policy.id,
        { runId: content.creationRunId }, connection);
      return row;
    });
  }

  private async projectGrants(content: CustodyContent, connection: Queryable) {
    const actions = new Map<string, Set<string>>();
    const add = (binding: BoundKeys, values: string[]) => {
      const current = actions.get(binding.principalId) ?? new Set<string>();
      values.forEach(value => current.add(value));
      actions.set(binding.principalId, current);
    };
    for (const reader of content.policy.readers) add(reader, ['read', 'reveal']);
    for (const authority of content.policy.authorities) add(authority, ['read', 'reveal', 'update', 'share', 'use']);
    for (const grant of content.policy.grants) {
      add(grant.actor, ['read', 'use']);
      add(grant.executor, ['read', 'use']);
    }
    await connection.query('DELETE FROM grants WHERE resource_id=$1', [content.policy.id]);
    for (const [principal, values] of actions) await connection.query(
      'INSERT INTO grants(resource_id,principal_id,actions) VALUES($1,$2,$3)',
      [content.policy.id, principal, [...values]],
    );
  }
}
