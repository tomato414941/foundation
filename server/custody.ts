import type { Actor } from './authorization.js';
import { principal } from './authorization.js';
import { z } from 'zod';
import type { Queryable } from './database.js';
import type { Resources, ResourceRow } from './resources.js';
import type { Bindings } from './bindings.js';
import { canonical, hash } from '../shared/authority.js';
import type { BoundKeys } from '../shared/authority.js';
import { ContentTypes, grantActive, ProtectedContent, contentLimit, continuesPolicy, policyAuthority, verifyContent } from '../shared/custody.js';
import type { CustodyContent, CustodyPolicy } from '../shared/custody.js';
import type { JsonValue } from '../shared/contracts.js';
import { Id } from '../shared/contracts.js';
import { AppMetadata, ConnectionMetadata, ConnectionSettings } from '../shared/connections.js';
import type { ConnectionLabelValues } from '../shared/connections.js';
import { kindOf } from '../shared/protected.js';
import { project } from './relations.js';
import type { Relations } from './relations.js';
import { fail } from './errors.js';
import { SharedReceipt, verifyReceipt } from '../shared/runtime-protocol.js';
import type { SharedResultReceipt } from '../shared/runtime-protocol.js';
import type { SealedRun } from '../shared/custody.js';

export interface ProtectedWrite {
  name: string;
  content: CustodyContent;
  labels?: ConnectionLabelValues;
  data?: Record<string, JsonValue>;
  version?: number;
}
// Whom an item is shared with besides its signer: who opens it, signs for it, sees it, or has it used for them.
// Signing an item is not sharing it, so one who may change it may still not change these. Expired grants give nothing.
function sharedWith(policy: CustodyPolicy, signer: BoundKeys, now = Date.now()) {
  const others = (values: BoundKeys[]) => [...new Set(values.map(value => value.principalId))].filter(id => id !== signer.principalId).sort();
  return {
    readers: others(policy.readers), authorities: others(policy.authorities),
    observers: [...new Set(policy.observers ?? [])].filter(id => id !== signer.principalId).sort(),
    grants: policy.grants.filter(grant => grantActive(grant, now) && !('actor' in grant && grant.actor.principalId === signer.principalId))
      .map(grant => canonical(grant)).sort(),
  };
}
// Whether the signer continues an item it signed for with keys it has since replaced. Those keys can no longer hand it
// over, so the signer seals a new value with its current keys, and what they sealed cannot be opened again.
export const succeeds = (policy: CustodyPolicy, signer: BoundKeys) =>
  !policy.authorities.some(authority => canonical(authority) === canonical(signer)) &&
  policy.authorities.some(authority => authority.principalId === signer.principalId);
// Labels stay with the item until a writer gives new ones.
const keptLabels = (data: Record<string, JsonValue> | undefined) => {
  const settings = ConnectionSettings.safeParse(data?.settings);
  return { ...Object.fromEntries(['methodName', 'account'].filter(key => typeof data?.[key] === 'string').map(key => [key, data![key]!])),
    ...(settings.success ? { settings: settings.data } : {}) };
};

export class Custody {
  constructor(
    readonly resources: Resources,
    readonly bindings: Bindings,
    readonly relations: Relations,
    readonly origin: string,
  ) {}

  metadata(content: CustodyContent) {
    const schema = content.policy.contentType === ContentTypes.tokenSet ? ConnectionMetadata
      : content.policy.contentType === ContentTypes.clientCredential
        ? AppMetadata : z.object({ bytes: z.number().int().min(0)
          .max(contentLimit(content.policy.contentType)) }).strict();
    if (!schema.safeParse(content.metadata).success)
      fail(400, 'invalid_metadata', 'Provide only the public metadata for this protected item.');
    return content.metadata;
  }
  private async references(actor: Actor, content: CustodyContent, connection: Queryable) {
    const values = content.policy.contentType === ContentTypes.value ? [] : [
      ...(Id.safeParse(content.metadata.methodId).success ? [{ id: String(content.metadata.methodId), kind: 'method' }] : []),
      ...(content.metadata.appId ? [{ id: String(content.metadata.appId), kind: 'app' }] : []),
    ];
    for (const value of values) {
      const row = await this.resources.get(value.id, connection);
      if (row.kind !== value.kind) fail(400, 'wrong_kind', 'Choose a matching connection method and application.');
      await this.resources.authorization.requireResource(actor, row, 'use', connection);
    }
    await this.resources.references(content.policy.id, values.map(value => value.id), connection);
  }
  private async replacePending(previous: CustodyContent, next: CustodyContent, connection: Queryable) {
    const pending = await this.resources.db.one<{ id: string; state: string }>(
      "SELECT id,state FROM connection_operations WHERE resource_id=$1 AND state IN ('prepared','in_flight','uncertain')",
      [previous.policy.id], connection);
    if (!pending) return;
    // A fresh, owner-approved authorization supersedes an ambiguous old token
    // generation. Resharing the existing generation must remain frozen.
    if (pending.state !== 'uncertain' || next.policy.contentType !== ContentTypes.tokenSet ||
      next.metadata.generation === previous.metadata.generation)
      fail(409, 'connection_busy', 'Resolve the current token update or approve a new connection before changing it.');
    await connection.query("UPDATE connection_operations SET state='aborted',updated_at=now() WHERE id=$1", [pending.id]);
  }

  async get(id: string, connection: Queryable = this.resources.db.pool): Promise<CustodyContent> {
    const row = await this.resources.db.one<{ content: CustodyContent }>(
      'SELECT content FROM resource_custody WHERE resource_id=$1', [id], connection,
    );
    if (row) return ProtectedContent.parse(row.content);
    const result = await this.resources.db.one<{ content: CustodyContent }>(
      "SELECT receipt->'content' AS content FROM execution_tasks WHERE id=$1 AND receipt ? 'content'", [id], connection);
    if (!result) fail(409, 'custody_required', 'Encrypt this item for its readers and execution environments.');
    return ProtectedContent.parse(result.content);
  }

  // Items this identity can seal again without anyone deciding anything: those still encrypted for executors whose
  // grants have expired and, where it acts as the owner, those whose readers no longer match who may open them: not
  // yet sealed for everyone who uses what the owner holds, as for a new delegate, still sealed for one that may no
  // longer open them, as for a delegate whose line was erased, or sealed for keys that someone has since replaced. The
  // server cannot do it, because only the item's readers can open it. The list only says where to look, and each item
  // is sealed again on its own.
  async pending(actor: Actor, principalId: string) {
    if (actor.id !== principalId || actor.requestId) fail(403, 'forbidden', 'Sign in as this principal to protect its items.');
    const { binding } = await this.bindings.current(principalId);
    type Row = { id: string; kind: string; owner_id: string; readers: BoundKeys[]; authorities: BoundKeys[];
      grants: Array<{ executor: BoundKeys; actor?: BoundKeys; expiresAt: string | null }> };
    const rows = await this.resources.db.all<Row>(
      `SELECT c.resource_id AS id, r.kind, r.owner_id, c.content->'policy'->'readers' AS readers,
         c.content->'policy'->'authorities' AS authorities, c.content->'policy'->'grants' AS grants
       FROM resource_custody c JOIN resources r ON r.id=c.resource_id
       WHERE EXISTS (SELECT 1 FROM jsonb_array_elements(c.content->'policy'->'authorities') a WHERE a->>'id'=$1)
       UNION ALL
       SELECT t.id, 'result', t.owner_id, t.receipt->'content'->'policy'->'readers',
         t.receipt->'content'->'policy'->'authorities', t.receipt->'content'->'policy'->'grants'
       FROM execution_tasks t WHERE t.receipt ? 'content'
         AND EXISTS (SELECT 1 FROM jsonb_array_elements(t.receipt->'content'->'policy'->'authorities') a WHERE a->>'id'=$1)
       ORDER BY 1`, [binding.id]);
    const named = (row: Row) => [...row.readers, ...row.authorities,
      ...(row.grants ?? []).flatMap(grant => grant.actor ? [grant.actor, grant.executor] : [grant.executor])];
    const current = new Map((await this.resources.db.all<{ principal_id: string; id: string }>(
      "SELECT principal_id,binding->>'id' AS id FROM principal_key_bindings WHERE retired_at IS NULL AND principal_id=ANY($1::uuid[])",
      [[...new Set(rows.flatMap(row => named(row).map(value => value.principalId)))]])).map(row => [row.principal_id, row.id]));
    const replaced = (row: Row) => named(row).some(value => current.has(value.principalId) && current.get(value.principalId) !== value.id);
    const owners = new Set(await this.resources.authorization.find(principalId, 'principal', 'stands'));
    const recipients = new Map<string, string[]>();
    // A reader may open an item it may reveal, and a result of a principal it may read; one who runs with an item
    // may use it. Each is looked up once for each principal it is sealed for.
    const found = new Map<string, Set<string>>();
    const may = async (principal: string, row: Row, permission: 'open' | 'use') => {
      const [type, name] = row.kind === 'result' ? ['principal', 'read'] : [row.kind, permission === 'open' ? 'reveal' : 'use'];
      const key = [principal, type, name].join(':');
      if (!found.has(key)) found.set(key, new Set(await this.resources.authorization.find(principal, type, name)));
      return found.get(key)!.has(row.kind === 'result' ? row.owner_id : row.id);
    };
    const items: Array<{ id: string; reason: 'grantExpired' | 'recipients'; remove: string[] }> = [];
    for (const row of rows) {
      const grants = row.grants ?? [], expired = grants.some(grant => !grantActive(grant));
      if (!owners.has(row.owner_id)) {
        if (expired) items.push({ id: row.id, reason: 'grantExpired', remove: [] });
        continue;
      }
      if (!recipients.has(row.owner_id))
        recipients.set(row.owner_id, (await this.recipients(row.owner_id)).map(recipient => recipient.binding.id));
      const remove = new Set<string>();
      for (const reader of row.readers) if (!(await may(reader.principalId, row, 'open'))) remove.add(reader.principalId);
      for (const grant of grants) if (grant.actor && !(await may(grant.actor.principalId, row, 'use'))) remove.add(grant.actor.principalId);
      if (remove.size || recipients.get(row.owner_id)!.some(id => !row.readers.some(reader => reader.id === id)) || replaced(row))
        items.push({ id: row.id, reason: 'recipients', remove: [...remove] });
      else if (expired) items.push({ id: row.id, reason: 'grantExpired', remove: [] });
    }
    return items;
  }

  async recipients(ownerId: string, connection: Queryable = this.resources.db.pool) {
    return this.bound(await this.resources.recipients(ownerId, connection), connection);
  }
  async required(ownerId: string, connection: Queryable = this.resources.db.pool) {
    return this.bound(await this.resources.required(ownerId, connection), connection);
  }
  // Delegates of the owner who are not among those who must open what it holds.
  async delegates(ownerId: string, connection: Queryable = this.resources.db.pool) {
    const required = new Set((await this.resources.required(ownerId, connection)).map(principal => principal.id));
    return this.bound((await this.resources.recipients(ownerId, connection)).filter(principal => !required.has(principal.id)), connection);
  }
  private bound(principals: Array<{ id: string; name: string }>, connection: Queryable) {
    return Promise.all(principals.map(async principal => ({
      name: principal.name, ...(await this.bindings.current(principal.id, connection)),
    })));
  }

  async read(actor: Actor, id: string) {
    await this.resources.authorization.active(actor);
    const content = await this.get(id);
    const { binding } = await this.bindings.current(actor.id);
    const granted = content.policy.grants.filter(grant => grantActive(grant));
    // Sealed for keys the reader has since replaced, the item still goes to it, to seal its next value with the
    // current keys; nothing opens what is sealed there.
    const sealed = content.policy.readers.some(reader => reader.principalId === binding.principalId);
    const executes = granted.some(grant => canonical(grant.executor) === canonical(binding));
    const requests = granted.some(grant => 'actor' in grant && canonical(grant.actor) === canonical(binding));
    if (!sealed && !executes && !requests) fail(403, 'forbidden', 'This identity is not a recipient of this item.');
    if (content.policy.contentType === ContentTypes.executionResult) {
      await this.resources.authorization.requirePrincipal(actor, content.policy.ownerId, 'read');
      return { content, version: content.materialRevision };
    }
    const row = await this.resources.get(id), { authorization } = this.resources;
    // Being sealed for is not enough: the item goes to a reader that may still reveal it, to one that runs with it that
    // may still use it, and to an executor that may read it. An erased line thus takes effect before the owner's
    // devices seal the item again without that reader.
    if (!(sealed && await authorization.can(actor, row, 'reveal')) && !(requests && await authorization.can(actor, row, 'use')) &&
      !(executes && await authorization.can(actor, row, 'read')))
      fail(403, 'forbidden', 'This identity may no longer open this item.');
    return { content, version: row.version };
  }

  async putResult(actor: Actor, input: ProtectedWrite, transaction?: Queryable, requiredReaders?: BoundKeys[]) {
    const persist = async (connection: Queryable) => {
      await this.resources.authorization.active(actor);
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      const row = await this.resources.db.one<{ owner_id: string; request: SealedRun; receipt: SharedResultReceipt }>(
        "SELECT owner_id,request,receipt FROM execution_tasks WHERE id=$1 AND receipt ? 'content' FOR UPDATE",
        [input.content.policy.id], connection);
      if (!row) fail(404, 'not_found', 'This execution has no protected result.');
      const previous = SharedReceipt.parse(row.receipt).content;
      const content = await verifyContent(input.content), policy = content.policy;
      this.metadata(content);
      const { binding } = await this.bindings.current(actor.id, connection);
      if (policy.origin !== this.origin ||
        content.signerId !== binding.id || canonical(policyAuthority(content)) !== canonical(binding) ||
        !previous.policy.authorities.some(authority => canonical(authority) === canonical(binding)))
        fail(403, 'forbidden', 'An existing authority must sign changes to the result readers.');
      if (policy.ownerId !== row.owner_id) {
        await this.resources.authorization.requirePrincipal(actor, row.owner_id, 'update', connection);
        if (actor.agreedBy !== policy.ownerId && actor.id !== policy.ownerId)
          fail(403, 'handoff_required', 'The new owner must agree to receive the protected result.');
        await this.resources.authorization.requirePrincipal({ id: actor.agreedBy ?? actor.id }, policy.ownerId, 'create', connection);
      } else await this.resources.authorization.requirePrincipal(actor, row.owner_id, 'update', connection);
      if (input.version !== previous.materialRevision || content.materialRevision !== previous.materialRevision + 1 ||
        policy.revision !== previous.policy.revision + (canonical(previous.policy) === canonical(policy) ? 0 : 1) ||
        canonical(content.metadata) !== canonical(previous.metadata))
        fail(409, 'changed', 'Review the current result before changing its readers.');
      for (const reader of [...policy.readers, ...policy.authorities]) await this.bindings.requireCurrent(reader, connection);
      for (const reader of requiredReaders ?? (await this.required(policy.ownerId, connection)).map(item => item.binding))
        if (!policy.readers.some(next => canonical(next) === canonical(reader)))
          fail(400, 'missing_recipient', 'Include every owner and member as an encrypted recipient.');
      const next = { ...row.receipt, content };
      await verifyReceipt(next, row.request.intent);
      await connection.query('UPDATE execution_tasks SET receipt=$2,owner_id=$3 WHERE id=$1', [policy.id, JSON.stringify(next), policy.ownerId]);
      await this.resources.audit.record(policy.ownerId, actor.id, 'result.protect', policy.id,
        { policyRevision: policy.revision, materialRevision: content.materialRevision }, connection);
      return { content, version: content.materialRevision };
    };
    return transaction ? persist(transaction) : this.resources.db.transaction(persist);
  }

  async put(actor: Actor, input: ProtectedWrite, transaction?: Queryable, requiredReaders?: BoundKeys[]) {
    const content = await verifyContent(input.content), policy = content.policy;
    if (policy.contentType === ContentTypes.executionResult)
      fail(400, 'wrong_kind', 'Use the protected result endpoint for execution results.');
    this.metadata(content);
    if (input.data && canonical(input.data) !== canonical(content.metadata))
      fail(400, 'invalid_metadata', 'Sign the public metadata together with its encrypted content.');
    if (policy.origin !== this.origin) fail(400, 'wrong_origin', 'This content belongs to another Foundation server.');
    const { binding } = await this.bindings.current(actor.id);
    if (content.signerId !== binding.id || canonical(policyAuthority(content)) !== canonical(binding))
      fail(403, 'forbidden', 'Sign this change as an authorized editor of the item.');
    const allBindings = [...policy.readers, ...policy.authorities,
      ...policy.grants.flatMap(grant => 'actor' in grant ? [grant.actor, grant.executor] : [grant.executor])];
    for (const keys of new Map(allBindings.map(keys => [keys.id, keys])).values())
      await this.bindings.requireCurrent(keys);
    const persist = async (connection: Queryable) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      if (await this.resources.db.one('SELECT 1 FROM execution_tasks WHERE id=$1', [policy.id], connection))
        fail(409, 'id_in_use', 'Choose a protected content ID that is not used by an execution.');
      const current = await this.resources.db.one<ResourceRow>(
        'SELECT * FROM resources WHERE id=$1 FOR UPDATE', [policy.id], connection,
      );
      let sealed = false;
      if (current) {
        if (current.kind !== kindOf(policy.contentType))
          fail(400, 'wrong_resource', 'Keep the same resource kind when updating an item.');
        if (current.owner_id === policy.ownerId) await this.resources.authorization.requireResource(actor, current, 'update', connection);
        else {
          await this.resources.authorization.requireResource(actor, current, 'transfer', connection);
          await this.resources.principals.get(policy.ownerId, connection);
        }
        if (current.version !== input.version) fail(409, 'changed', 'This item changed. Reload it before saving.');
        const previous = await this.resources.db.one<{ content: CustodyContent }>(
          'SELECT content FROM resource_custody WHERE resource_id=$1', [policy.id], connection,
        );
        if (previous && !succeeds(previous.content.policy, binding)) {
          if (!previous.content.policy.authorities.some(authority => canonical(authority) === canonical(binding)))
            fail(403, 'forbidden', 'The existing policy must authorize its editor.');
          if (!continuesPolicy(previous.content.policy, content))
            fail(403, 'handoff_required', 'Authorize new ownership and editors with the existing authority.');
        }
        if (previous) {
          if (policy.ownerId !== previous.content.policy.ownerId && succeeds(previous.content.policy, binding))
            fail(403, 'handoff_required', 'Seal the item for its current owner before passing it on.');
          if (canonical(sharedWith(previous.content.policy, binding)) !== canonical(sharedWith(policy, binding)))
            await this.resources.authorization.requireResource(actor, current, 'share', connection);
          sealed = true;
          const policyChanged = await hash(previous.content.policy) !== await hash(policy);
          if (policy.revision !== previous.content.policy.revision + (policyChanged ? 1 : 0) ||
            content.materialRevision !== previous.content.materialRevision + 1)
            fail(409, 'changed', 'Advance the current content and policy revisions.');
          await this.replacePending(previous.content, content, connection);
        } else {
          await this.resources.authorization.requireResource(actor, current, 'reveal', connection);
          if (policy.revision !== 1 || content.materialRevision !== 1)
            fail(400, 'invalid_revision', 'Begin encrypted custody at revision one.');
        }
      } else {
        if (!(await this.resources.authorization.canCreate(actor, policy.ownerId, kindOf(policy.contentType), connection)))
          fail(403, 'forbidden', 'You cannot create this item for this principal.');
        if (policy.revision !== 1 || content.materialRevision !== 1)
          fail(400, 'invalid_revision', 'Begin encrypted custody at revision one.');
      }
      const required = requiredReaders ?? (await this.required(policy.ownerId, connection)).map(item => item.binding);
      for (const recipient of required) {
        if (!policy.readers.some(reader => canonical(reader) === canonical(recipient)))
          fail(400, 'missing_recipient', 'Include every owner and member as an encrypted recipient.');
      }
      // Sealing something for the first time shares it beyond those who open what the owner holds only by one who
      // may share what the owner holds.
      if (!sealed) {
        const expected = sharedWith({ ...policy, readers: required, authorities: required, observers: [], grants: [] }, binding).readers;
        const given = sharedWith(policy, binding);
        if ([...given.readers, ...given.authorities].some(id => !expected.includes(id)) || given.observers.length || given.grants.length)
          await this.resources.authorization.requirePrincipal(actor, policy.ownerId, 'share', connection);
      }
      // Sealing it for another owner passes it on, which the new owner agrees to as to anything passed to it.
      if (current && current.owner_id !== policy.ownerId)
        await this.relations.agree(actor, { kind: 'transfer', itemId: current.id, to: policy.ownerId },
          this.relations.handing(current, policy.ownerId), connection);
      const data = { ...keptLabels(current?.data), ...content.metadata, ...(input.labels ?? {}),
        recipients: policy.readers.map(reader => reader.principalId),
        executors: [...new Set(policy.grants.map(grant => grant.executor.principalId))],
        custodyRevision: policy.revision };
      let row: ResourceRow;
      if (current) {
        row = await this.resources.update(current, { name: input.name, data }, connection);
        await connection.query('UPDATE resources SET private_data=NULL,sealed=NULL,owner_id=$2 WHERE id=$1', [policy.id, policy.ownerId]);
        row = { ...row, owner_id: policy.ownerId, private_data: null, sealed: null };
      } else row = await this.resources.insert(policy.ownerId, kindOf(policy.contentType), input.name,
        data, { id: policy.id }, connection);
      await this.projectGrants(content, connection);
      await connection.query(
        'INSERT INTO resource_custody(resource_id,content) VALUES($1,$2) ON CONFLICT(resource_id) DO UPDATE SET content=EXCLUDED.content',
        [policy.id, JSON.stringify(content)],
      );
      await this.references(actor, content, connection);
      await this.resources.audit.record(policy.ownerId, actor.id, 'resource.protect', policy.id,
        { policyRevision: policy.revision, materialRevision: content.materialRevision }, connection);
      return row;
    };
    return transaction ? persist(transaction) : this.resources.db.transaction(persist);
  }

  async putProduced(actor: Actor, input: ProtectedWrite) {
    const content = await verifyContent(input.content), policy = content.policy;
    if (policy.contentType === ContentTypes.executionResult)
      fail(400, 'wrong_kind', 'Deliver protected results together with their execution receipts.');
    this.metadata(content);
    const { binding } = await this.bindings.current(actor.id);
    if (policy.origin !== this.origin || content.signerId !== binding.id || !content.creationRunId)
      fail(403, 'forbidden', 'Store output from an execution approved for this identity.');
    const stored = await this.resources.db.one<{ content: CustodyContent }>(
      'SELECT content FROM resource_custody WHERE resource_id=$1', [policy.id]);
    if (stored && canonical(stored.content) === canonical(content)) return this.resources.get(policy.id);
    const producer = policy.producers.find(producer => producer.runId === content.creationRunId &&
      producer.materialRevision === content.materialRevision && canonical(producer.executor) === canonical(binding) &&
      Date.parse(producer.expiresAt) > Date.now());
    if (!producer) fail(403, 'forbidden', 'Approve this execution before saving its output.');
    const authority = policyAuthority(content);
    await this.bindings.requireCurrent(authority);
    const task = await this.resources.db.one<{ request: { intent: { actor: BoundKeys; ownerId: string; executor: BoundKeys } } }>(
      "SELECT request FROM execution_tasks WHERE id=$1 AND phase='dispatched' AND state IN ('running','uncertain')",
      [content.creationRunId],
    );
    const invocation = !task ? await this.resources.db.one<{ owner_id: string; executor: BoundKeys;
      request: { actor: BoundKeys | null; outputs: Record<string, { approval: { policy: CustodyPolicy; signature: string } }> } }>(
      "SELECT owner_id,executor,request FROM function_invocations WHERE id=$1 AND phase='dispatched' AND state IN ('running','uncertain')",
      [content.creationRunId]) : null;
    const authorized = task ? task.request.intent.ownerId === policy.ownerId &&
      canonical(task.request.intent.actor) === canonical(authority) && canonical(task.request.intent.executor) === canonical(binding)
      : invocation && invocation.owner_id === policy.ownerId && canonical(invocation.request.actor) === canonical(authority) &&
        canonical(invocation.executor) === canonical(binding) && Object.values(invocation.request.outputs).some(output =>
          canonical(output.approval.policy) === canonical(policy) && output.approval.signature === content.authorization);
    if (!authorized)
      fail(403, 'forbidden', 'Use the output destination approved by this execution requester.');
    return this.resources.db.transaction(async connection => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      if (await this.resources.db.one('SELECT 1 FROM execution_tasks WHERE id=$1', [policy.id], connection))
        fail(409, 'id_in_use', 'Choose a protected content ID that is not used by an execution.');
      const current = await this.resources.db.one<ResourceRow>('SELECT * FROM resources WHERE id=$1 FOR UPDATE', [policy.id], connection);
      if (current) {
        const previous = await this.get(policy.id, connection);
        if (canonical(previous) === canonical(content)) return current;
        await this.resources.authorization.requireResource({ id: authority.principalId }, current, 'update', connection);
        if (current.owner_id !== policy.ownerId || current.kind !== kindOf(policy.contentType) ||
          !(previous.policy.authorities.some(value => canonical(value) === canonical(authority)) || succeeds(previous.policy, authority)) ||
          content.materialRevision !== previous.materialRevision + 1 ||
          policy.revision !== previous.policy.revision + (await hash(policy) === await hash(previous.policy) ? 0 : 1))
          fail(409, 'changed', 'Review the current output destination before replacing it.');
        await this.replacePending(previous, content, connection);
      } else {
        if (content.materialRevision !== 1 || policy.revision !== 1)
          fail(400, 'invalid_revision', 'Start a new output at revision one.');
        if (!(await this.resources.authorization.canCreate({ id: authority.principalId }, policy.ownerId, kindOf(policy.contentType), connection)))
          fail(403, 'forbidden', 'The execution requester cannot create this output.');
      }
      for (const recipient of await this.required(policy.ownerId, connection))
        if (!policy.readers.some(reader => canonical(reader) === canonical(recipient.binding)))
          fail(400, 'missing_recipient', 'Include every owner and member as an encrypted recipient.');
      const data = { ...keptLabels(current?.data), ...content.metadata, ...(input.labels ?? {}),
        recipients: policy.readers.map(reader => reader.principalId),
        executors: [...new Set(policy.grants.map(grant => grant.executor.principalId))], custodyRevision: policy.revision };
      const row = current
        ? await this.resources.update(current, { name: input.name, data }, connection)
        : await this.resources.insert(policy.ownerId, kindOf(policy.contentType), input.name, data, { id: policy.id }, connection);
      await this.projectGrants(content, connection);
      await connection.query(
        'INSERT INTO resource_custody(resource_id,content) VALUES($1,$2) ON CONFLICT(resource_id) DO UPDATE SET content=EXCLUDED.content',
        [policy.id, JSON.stringify(content)],
      );
      await this.references({ id: authority.principalId }, content, connection);
      await this.resources.audit.record(policy.ownerId, actor.id, 'resource.capture', policy.id,
        { runId: content.creationRunId }, connection);
      return row;
    });
  }

  // Who holds which role on the item, as its signed policy says: a reader opens it, an observer only sees it is there,
  // an authority changes it and its policy, and a grant lets an actor use it on an executor. Whoever uses what the owner
  // holds has these roles through its line to the owner, and an erased line takes them away at once, so the item records
  // them only for others. One the item is still sealed for after its line was erased gains nothing here from that, until
  // the owner's devices seal the item again without it. This runs before the new content replaces the previous one.
  private async projectGrants(content: CustodyContent, connection: Queryable) {
    const { policy } = content, holders = new Set(await this.resources.authorization.holders(principal(policy.ownerId), 'use', connection));
    const previous = await this.resources.db.one<{ content: CustodyContent }>(
      'SELECT content FROM resource_custody WHERE resource_id=$1', [policy.id], connection);
    const named = new Set(previous ? [...previous.content.policy.readers, ...previous.content.policy.authorities,
      ...previous.content.policy.grants.flatMap(grant => 'actor' in grant ? [grant.actor, grant.executor] : [grant.executor])]
      .map(binding => binding.principalId).concat(previous.content.policy.observers ?? []) : []);
    const recorded = new Set((await this.resources.db.all<{ subject_id: string }>(
      'SELECT DISTINCT subject_id FROM relations WHERE resource_id=$1', [policy.id], connection)).map(row => row.subject_id));
    const lines = new Map<string, { subjectId: string; relation: string }>();
    const add = (subjectId: string, relations: string[]) => {
      if (holders.has(subjectId) || (named.has(subjectId) && !recorded.has(subjectId))) return;
      for (const relation of relations) lines.set(subjectId + '#' + relation, { subjectId, relation });
    };
    for (const reader of content.policy.readers) add(reader.principalId, ['reader', 'revealer']);
    for (const observer of content.policy.observers ?? []) add(observer, ['reader']);
    for (const authority of content.policy.authorities) add(authority.principalId, ['reader', 'revealer', 'editor', 'user']);
    for (const grant of content.policy.grants) {
      if ('actor' in grant) add(grant.actor.principalId, ['reader', 'user']);
      add(grant.executor.principalId, ['reader', 'user']);
    }
    await project(connection, content.policy.id, [...lines.values()]);
  }

}
