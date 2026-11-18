import type { Actor } from './authorization.js';
import { principal } from './authorization.js';
import { z } from 'zod';
import type { Queryable } from './database.js';
import type { Resources, ResourceRow } from './resources.js';
import type { Bindings } from './bindings.js';
import { canonical, hash } from '../shared/authority.js';
import type { BoundKeys } from '../shared/authority.js';
import { ContentTypes, ProtectedContent, contentLimit, continuesPolicy, policyAuthority, verifyContent } from '../shared/custody.js';
import type { CustodyContent, PolicyParties } from '../shared/custody.js';
import type { JsonValue } from '../shared/contracts.js';
import { Id } from '../shared/contracts.js';
import { AppMetadata, ConnectionMetadata } from '../shared/connections.js';
import type { ConnectionLabelValues } from '../shared/connections.js';
import { kindOf } from '../shared/protected.js';
import { project } from './relations.js';
import type { Relations } from './relations.js';
import { fail } from './errors.js';

export interface ProtectedWrite {
  name: string;
  content: CustodyContent;
  labels?: ConnectionLabelValues;
  data?: Record<string, JsonValue>;
  version?: number;
}
// Whom an item is shared with besides its signer: who opens it, signs for it, or sees it. Signing an item is not sharing
// it, so one who may change it may still not change these.
function sharedWith(policy: PolicyParties, signer: BoundKeys) {
  const others = (values: BoundKeys[]) => [...new Set(values.map(value => value.principalId))].filter(id => id !== signer.principalId).sort();
  return {
    readers: others(policy.readers), authorities: others(policy.authorities),
    observers: [...new Set(policy.observers ?? [])].filter(id => id !== signer.principalId).sort(),
  };
}
// Whether the signer continues an item it signed for with keys it has since replaced. Those keys can no longer hand it
// over, so the signer seals a new value with its current keys, and what they sealed cannot be opened again.
export const succeeds = (policy: Pick<PolicyParties, 'authorities'>, signer: BoundKeys) =>
  !policy.authorities.some(authority => canonical(authority) === canonical(signer)) &&
  policy.authorities.some(authority => authority.principalId === signer.principalId);
// Labels stay with the item until a writer gives new ones.
const keptLabels = (data: Record<string, JsonValue> | undefined): Record<string, JsonValue> =>
  typeof data?.account === 'string' ? { account: data.account } : {};

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
        ? AppMetadata : z.object({ bytes: z.number().int().min(0).max(contentLimit) }).strict();
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

  // The item as sealed. One still sealed in an earlier form opens on no device any more: it is deleted, and connected or
  // saved again.
  async get(id: string, connection: Queryable = this.resources.db.pool): Promise<CustodyContent> {
    const row = await this.resources.db.one<{ content: { policy?: { format?: unknown } } }>(
      'SELECT content FROM resource_custody WHERE resource_id=$1', [id], connection,
    );
    if (!row) fail(409, 'custody_required', 'Encrypt this item for its readers.');
    if (row.content.policy?.format !== 3)
      fail(409, 'content_outdated', 'This item is sealed in an earlier form that no device opens. Delete it, then connect or save it again.');
    return ProtectedContent.parse(row.content);
  }

  // Items this identity can seal again without anyone deciding anything, where it uses what the owner holds: those whose
  // readers no longer match who may open them: not yet sealed for everyone who uses what the owner holds, as for a new
  // delegate, still sealed for one that may no longer open them, as for a delegate whose line was erased, or sealed for
  // keys that someone has since replaced. The server cannot do it, because only the item's readers can open it. The list
  // only says where to look, and each item is sealed again on its own. An item sealed in an earlier form opens nowhere,
  // so it is left out.
  async pending(actor: Actor, principalId: string) {
    if (actor.id !== principalId || actor.requestId) fail(403, 'forbidden', 'Sign in as this principal to protect its items.');
    const { binding } = await this.bindings.current(principalId);
    type Row = { id: string; kind: string; owner_id: string; readers: BoundKeys[]; authorities: BoundKeys[] };
    const rows = await this.resources.db.all<Row>(
      `SELECT c.resource_id AS id, r.kind, r.owner_id, c.content->'policy'->'readers' AS readers,
         c.content->'policy'->'authorities' AS authorities
       FROM resource_custody c JOIN resources r ON r.id=c.resource_id
       WHERE c.content->'policy'->>'format'='3'
         AND EXISTS (SELECT 1 FROM jsonb_array_elements(c.content->'policy'->'authorities') a WHERE a->>'id'=$1)
       ORDER BY 1`, [binding.id]);
    const named = (row: Row) => [...row.readers, ...row.authorities];
    const current = new Map((await this.resources.db.all<{ principal_id: string; id: string }>(
      "SELECT principal_id,binding->>'id' AS id FROM principal_key_bindings WHERE retired_at IS NULL AND principal_id=ANY($1::uuid[])",
      [[...new Set(rows.flatMap(row => named(row).map(value => value.principalId)))]])).map(row => [row.principal_id, row.id]));
    const replaced = (row: Row) => named(row).some(value => current.has(value.principalId) && current.get(value.principalId) !== value.id);
    const owners = new Set(await this.resources.authorization.find(principalId, 'principal', 'use'));
    const recipients = new Map<string, string[]>();
    // Whether a reader may still open an item, looked up once for each principal it is sealed for.
    const found = new Map<string, Set<string>>();
    const opens = async (principal: string, row: Row) => {
      const key = principal + ':' + row.kind;
      if (!found.has(key)) found.set(key, new Set(await this.resources.authorization.find(principal, row.kind, 'reveal')));
      return found.get(key)!.has(row.id);
    };
    const items: Array<{ id: string; remove: string[] }> = [];
    for (const row of rows) {
      if (!owners.has(row.owner_id)) continue;
      if (!recipients.has(row.owner_id))
        recipients.set(row.owner_id, (await this.recipients(row.owner_id)).map(recipient => recipient.binding.id));
      const remove = new Set<string>();
      for (const reader of row.readers) if (!(await opens(reader.principalId, row))) remove.add(reader.principalId);
      if (remove.size || recipients.get(row.owner_id)!.some(id => !row.readers.some(reader => reader.id === id)) || replaced(row))
        items.push({ id: row.id, remove: [...remove] });
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
    // Sealed for keys the reader has since replaced, the item still goes to it, to seal its next value with the
    // current keys; nothing opens what is sealed there.
    if (!content.policy.readers.some(reader => reader.principalId === binding.principalId))
      fail(403, 'forbidden', 'This identity is not a reader of this item.');
    const row = await this.resources.get(id);
    // Being sealed for is not enough: the item goes to a reader that may still reveal it. An erased line thus takes
    // effect before the owner's devices seal the item again without that reader.
    if (!await this.resources.authorization.can(actor, row, 'reveal'))
      fail(403, 'forbidden', 'This identity may no longer open this item.');
    return { content, version: row.version };
  }

  async put(actor: Actor, input: ProtectedWrite, transaction?: Queryable, requiredReaders?: BoundKeys[]) {
    return this.write(actor, input, transaction, requiredReaders);
  }

  async transfer(actor: Actor, id: string, to: string, input: ProtectedWrite & { version: number }, transaction?: Queryable) {
    if (input.content.policy.id !== id || input.content.policy.ownerId !== to)
      fail(400, 'wrong_content', 'Encrypt the selected item for the new owner specified by to.');
    return this.write(actor, input, transaction, undefined, { id, to });
  }

  private async write(actor: Actor, input: ProtectedWrite, transaction?: Queryable, requiredReaders?: BoundKeys[],
    transfer?: { id: string; to: string }) {
    const content = await verifyContent(input.content), policy = content.policy;
    this.metadata(content);
    if (input.data && canonical(input.data) !== canonical(content.metadata))
      fail(400, 'invalid_metadata', 'Sign the public metadata together with its encrypted content.');
    if (policy.origin !== this.origin) fail(400, 'wrong_origin', 'This content belongs to another Foundation server.');
    const allBindings = [...policy.readers, ...policy.authorities];
    const persist = async (connection: Queryable) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      const { binding } = await this.bindings.current(actor.id, connection);
      if (content.signerId !== binding.id || canonical(policyAuthority(content)) !== canonical(binding))
        fail(403, 'forbidden', 'Sign this change as an authorized editor of the item.');
      for (const keys of new Map(allBindings.map(keys => [keys.id, keys])).values())
        await this.bindings.requireCurrent(keys, connection);
      const current = await this.resources.db.one<ResourceRow>(
        'SELECT * FROM resources WHERE id=$1 FOR UPDATE', [policy.id], connection,
      );
      if (transfer && !current) fail(404, 'not_found', 'The item to transfer no longer exists.');
      let sealed = false;
      if (current) {
        if (current.kind !== kindOf(policy.contentType))
          fail(400, 'wrong_resource', 'Keep the same resource kind when updating an item.');
        await this.resources.authorization.requireResource(actor, current, transfer ? 'transfer' : 'update', connection);
        if (!transfer && current.owner_id !== policy.ownerId)
          fail(409, 'transfer_required', 'Use POST /api/resources/' + current.id + '/transfer to change the owner.');
        if (transfer) await this.resources.principals.get(transfer.to, connection);
        if (current.version !== input.version) fail(409, 'changed', 'This item changed. Reload it before saving.');
        const previous = await this.resources.db.one('SELECT 1 FROM resource_custody WHERE resource_id=$1', [policy.id], connection)
          ? { content: await this.get(policy.id, connection) } : undefined;
        if (previous && !succeeds(previous.content.policy, binding)) {
          if (!previous.content.policy.authorities.some(authority => canonical(authority) === canonical(binding)))
            fail(403, 'forbidden', 'The existing policy must authorize its editor.');
          if (!continuesPolicy(previous.content.policy, content))
            fail(403, 'handoff_required', 'Authorize new ownership and editors with the existing authority.');
        }
        if (previous) {
          if (policy.ownerId !== previous.content.policy.ownerId && succeeds(previous.content.policy, binding))
            fail(403, 'handoff_required', 'Seal the item for its current owner before passing it on.');
          const before = sharedWith(previous.content.policy, binding), after = sharedWith(policy, binding);
          const implicit = new Set((await this.resources.recipients(policy.ownerId, connection)).map(principal => principal.id));
          // Selecting verified keys within existing owner access does not grant or revoke a permission.
          const explicit = (sharing: typeof before) => ({ ...sharing,
            readers: sharing.readers.filter(id => !implicit.has(id)),
            authorities: sharing.authorities.filter(id => !implicit.has(id)) });
          if (canonical(explicit(before)) !== canonical(explicit(after)))
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
        const recipients = (await this.recipients(policy.ownerId, connection)).map(item => item.binding);
        const expected = sharedWith({ ...policy, readers: recipients, authorities: recipients, observers: [] }, binding).readers;
        const given = sharedWith(policy, binding);
        if ([...given.readers, ...given.authorities].some(id => !expected.includes(id)) || given.observers.length)
          await this.resources.authorization.requirePrincipal(actor, policy.ownerId, 'share', connection);
      }
      if (transfer && current)
        await this.relations.agree(actor, { kind: 'transfer', itemId: transfer.id, to: transfer.to },
          this.relations.handing(current, transfer.to), connection);
      const data = { ...keptLabels(current?.data), ...content.metadata, ...(input.labels ?? {}),
        recipients: policy.readers.map(reader => reader.principalId), custodyRevision: policy.revision };
      let row: ResourceRow;
      if (current) {
        row = await this.resources.update(current, { name: input.name, data }, connection);
        await connection.query('UPDATE resources SET private_data=NULL,sealed=NULL,owner_id=$2 WHERE id=$1', [policy.id, policy.ownerId]);
        row = { ...row, owner_id: policy.ownerId, private_data: null, sealed: null };
      } else row = await this.resources.insert(policy.ownerId, kindOf(policy.contentType), input.name,
        data, { id: policy.id }, connection);
      await this.projectRoles(content, connection);
      await connection.query(
        'INSERT INTO resource_custody(resource_id,content) VALUES($1,$2) ON CONFLICT(resource_id) DO UPDATE SET content=EXCLUDED.content',
        [policy.id, JSON.stringify(content)],
      );
      await this.references(actor, content, connection);
      await this.resources.audit.record(policy.ownerId, actor.id, 'resource.protect', policy.id,
        { policyRevision: policy.revision, materialRevision: content.materialRevision }, connection);
      if (transfer && current && current.owner_id !== transfer.to) {
        const agreement: Record<string, string> = actor.agreedBy ? { agreedBy: actor.agreedBy } : {};
        await this.resources.audit.record(transfer.to, actor.id, 'resource.receive', current.id,
          { from: current.owner_id, ...agreement }, connection);
        await this.resources.audit.record(current.owner_id, actor.id, 'resource.transfer', current.id,
          { to: transfer.to, ...agreement }, connection);
      }
      return row;
    };
    return transaction ? persist(transaction) : this.resources.db.transaction(persist);
  }

  // Who holds which role on the item, as its signed policy says: a reader opens it, an observer only sees it is there,
  // and an authority changes it and its policy. Whoever uses what the owner holds has these roles through its line to the
  // owner, and an erased line takes them away at once, so the item records them only for others. One the item is still
  // sealed for after its line was erased gains nothing here from that, until the owner's devices seal the item again
  // without it. This runs before the new content replaces the previous one.
  private async projectRoles(content: CustodyContent, connection: Queryable) {
    const { policy } = content, holders = new Set(await this.resources.authorization.holders(principal(policy.ownerId), 'use', connection));
    const previous = await this.resources.db.one('SELECT 1 FROM resource_custody WHERE resource_id=$1', [policy.id], connection)
      ? (await this.get(policy.id, connection)).policy : undefined;
    const named = new Set(previous ? [...previous.readers, ...previous.authorities]
      .map(binding => binding.principalId).concat(previous.observers ?? []) : []);
    const recorded = new Set((await this.resources.db.all<{ subject_id: string }>(
      'SELECT DISTINCT subject_id FROM relations WHERE resource_id=$1', [policy.id], connection)).map(row => row.subject_id));
    const lines = new Map<string, { subjectId: string; relation: string }>();
    const add = (subjectId: string, relations: string[]) => {
      if (holders.has(subjectId) || (named.has(subjectId) && !recorded.has(subjectId))) return;
      for (const relation of relations) lines.set(subjectId + '#' + relation, { subjectId, relation });
    };
    for (const reader of policy.readers) add(reader.principalId, ['reader', 'revealer']);
    for (const observer of policy.observers ?? []) add(observer, ['reader']);
    for (const authority of policy.authorities) add(authority.principalId, ['reader', 'revealer', 'editor', 'user']);
    await project(connection, policy.id, [...lines.values()]);
  }

}
