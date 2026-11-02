import type { z } from 'zod';
import { canonical, hash, verify, verifyBinding } from '../shared/authority.js';
import { continuesPolicy, policyAuthority, ProtectedContent, verifyContent } from '../shared/custody.js';
import { SignedEnvironment, verifyEnvironment, verifyReceipt } from '../shared/runtime-protocol.js';
import { openKeyring, keyringClaim } from '../shared/keyring.js';
import { verifyFunctionSettings } from '../shared/function-api.js';
import { rotationPolicy, rotationPreparationProof, RotationPayload } from '../shared/key-rotations.js';
import type { RotationKind, RotationPreparation, RotationStart, RotationView } from '../shared/key-rotations.js';
import { WrappedKey } from '../shared/contracts.js';
import { decodeProtectedHeader } from 'jose';
import type { Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor } from './authorization.js';
import type { Custody } from './custody.js';
import type { ResourceRow } from './resources.js';
import { DomainError, fail, required } from './errors.js';

type Kind = z.infer<typeof RotationKind>;
type Payload = z.infer<typeof RotationPayload>;
type View = z.infer<typeof RotationView>;
interface RotationRow {
  id: string; principal_id: string; previous: z.infer<typeof RotationStart>['replacement'];
  replacement: z.infer<typeof RotationStart>['replacement']; previous_signature: string;
  state: 'preparing' | 'committed' | 'cancelled'; completed_items: number;
  created_at: Date; finished_at: Date | null;
}
interface Item { kind: Kind; id: string; name: string; source: Record<string, unknown> }
interface Prepared {
  kind: Kind; item_id: string; source_digest: string; payload: Payload; signature: string;
}

export class KeyRotations {
  constructor(readonly custody: Custody) {}
  get db() { return this.custody.resources.db; }
  private async authorize(actor: Actor, principalId: string, connection: Queryable = this.db.pool) {
    if (actor.requestId) fail(403, 'forbidden', 'Use a principal credential to manage keys.');
    await this.custody.resources.authorization.requirePrincipal(actor, principalId, 'manage_credentials', connection);
  }
  private row(principalId: string, id: string, connection: Queryable = this.db.pool, lock = false) {
    return this.db.one<RotationRow>('SELECT * FROM key_rotations WHERE principal_id=$1 AND id=$2' +
      (lock ? ' FOR UPDATE' : ''), [principalId, id], connection).then(row => required(row));
  }
  private async checkCurrent(row: RotationRow, connection: Queryable) {
    const current = await this.custody.bindings.current(row.principal_id, connection);
    if (canonical(current) !== canonical(row.previous))
      fail(409, 'key_binding_changed', 'The principal changed its keys. Cancel this rotation and start again.');
    if (await this.db.one("SELECT 1 FROM challenges WHERE principal_id=$1 AND kind='key-reset' AND expires_at>now()",
      [row.principal_id], connection))
      fail(409, 'key_reset_pending', 'Cancel the pending key reset before rotating keys.');
  }
  private async checked<T>(operation: () => Promise<T>): Promise<T> {
    try { return await operation(); }
    catch (error) {
      if (error instanceof DomainError) throw error;
      fail(400, 'invalid_rotation_proof', 'Verify the signatures and encrypted preparation for this key rotation.');
    }
  }

  async start(actor: Actor, principalId: string, input: z.infer<typeof RotationStart>) {
    await this.authorize(actor, principalId);
    const replacement = await this.checked(() => verifyBinding(input.replacement));
    if (replacement.principalId !== principalId) fail(400, 'wrong_principal', 'Rotate keys for the selected principal.');
    return this.db.transaction(async connection => {
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [principalId]);
      const existing = await this.db.one<RotationRow>('SELECT * FROM key_rotations WHERE id=$1', [input.id], connection);
      if (existing) {
        if (existing.principal_id !== principalId || canonical(existing.replacement) !== canonical(input.replacement) ||
          existing.previous_signature !== input.previousSignature)
          fail(409, 'rotation_conflict', 'Use a new rotation ID for different replacement keys.');
        const items = existing.state === 'preparing' ? await this.items(existing, connection) : [];
        const prepared = await this.preparations(existing.id, connection);
        const count = (await Promise.all(items.map(async item => {
          const digest = await hash(item.source);
          return prepared.some(value => value.kind === item.kind && value.item_id === item.id && value.source_digest === digest);
        }))).filter(Boolean).length;
        return this.summary(existing, [], existing.state === 'preparing' ? await this.blockers(existing, items, connection) : [],
          existing.state === 'preparing' ? items.length : existing.completed_items, count);
      }
      const previous = await this.custody.bindings.current(principalId, connection);
      if (replacement.id === previous.binding.id || replacement.generation !== previous.binding.generation + 1 ||
        replacement.previous !== await hash(previous.binding) ||
        canonical(replacement.encryption) === canonical(previous.binding.encryption))
        fail(409, 'key_binding_changed', 'Link the next key generation to the current key binding.');
      await this.checked(() => verify(replacement, input.previousSignature, previous.binding.signing, 'key-replacement'));
      if (await this.db.one("SELECT 1 FROM key_rotations WHERE principal_id=$1 AND state='preparing'", [principalId], connection))
        fail(409, 'rotation_in_progress', 'Finish or cancel the current key rotation.');
      const row = required(await this.db.one<RotationRow>(
        'INSERT INTO key_rotations(id,principal_id,previous,replacement,previous_signature) VALUES($1,$2,$3,$4,$5) RETURNING *',
        [input.id, principalId, JSON.stringify(previous), JSON.stringify(input.replacement), input.previousSignature], connection));
      await this.checkCurrent(row, connection);
      await this.custody.resources.audit.record(principalId, actor.id, 'principal.startKeyRotation', row.id,
        { generation: replacement.generation }, connection);
      const items = await this.items(row, connection);
      return this.summary(row, [], await this.blockers(row, items, connection), items.length);
    });
  }

  private async items(row: RotationRow, connection: Queryable = this.db.pool,
    selected?: { kind: Kind; id: string }): Promise<Item[]> {
    const values = [row.previous.binding.id, row.principal_id, selected?.kind ?? null, selected?.id ?? null];
    const items = await this.db.all<Item>(
      "SELECT * FROM (SELECT 'content' AS kind,r.id,r.name,jsonb_build_object('version',r.version,'content',c.content) AS source " +
      "FROM resource_custody c JOIN resources r ON r.id=c.resource_id WHERE jsonb_path_exists(c.content->'policy'," +
      "'$.**.id ? (@ == $binding)',jsonb_build_object('binding',$1::text)) " +
      "UNION ALL SELECT 'result',t.id,'Execution result',jsonb_build_object('receipt',t.receipt,'intent',t.request->'intent') " +
      "FROM execution_tasks t WHERE t.receipt ? 'content' AND jsonb_path_exists(t.receipt#>'{content,policy}'," +
      "'$.**.id ? (@ == $binding)',jsonb_build_object('binding',$1::text)) " +
      "UNION ALL SELECT 'credential',c.id,c.name,jsonb_build_object('kind',c.kind,'wrappedKey',c.private_wrap) " +
      "FROM credentials c WHERE c.principal_id=$2 AND c.private_wrap IS NOT NULL " +
      "UNION ALL SELECT 'environment',r.id,r.name,jsonb_build_object('version',r.version,'registration',e.registration,'stoppedAt',e.stopped_at) " +
      "FROM executor_environments e JOIN resources r ON r.id=e.resource_id WHERE e.registration#>>'{manifest,executor,id}'=$1 " +
      "UNION ALL SELECT 'functionSettings',s.function_id,r.name,jsonb_build_object('version',s.version,'approval',s.approval) " +
      "FROM function_settings s JOIN resources r ON r.id=s.function_id WHERE s.approval#>>'{executor,id}'=$1) items " +
      "WHERE ($3::text IS NULL OR (kind=$3 AND id=$4::uuid))",
      values, connection);
    const keyrings = selected && selected.kind !== 'keyring' ? [] : await this.db.all<ResourceRow>(
      "SELECT * FROM resources WHERE kind='keyring' AND ($1::uuid IS NULL OR id=$1)", [selected?.id ?? null], connection);
    for (const keyring of keyrings) {
      let claim;
      try { claim = keyringClaim(String(keyring.data.signature)); }
      catch { continue; }
      if (claim.signerId === row.previous.binding.id)
        items.push({ kind: 'keyring', id: keyring.id, name: keyring.name,
          source: { version: keyring.version, signature: keyring.data.signature } });
    }
    return items.sort((a, b) => a.kind + ':' + a.id < b.kind + ':' + b.id ? -1 : 1);
  }
  private async blockers(row: RotationRow, items: Item[], connection: Queryable = this.db.pool) {
    const ids = [row.previous.binding.id, ...items.filter(item => item.kind === 'content').map(item => item.id)];
    const patterns = ids.map(id => '%' + id + '%');
    return this.db.all<{ kind: string; id: string; reason: string }>(
      "SELECT 'execution' AS kind,id,'execution_active' AS reason FROM execution_tasks " +
      "WHERE state IN ('queued','running','uncertain') AND request::text LIKE ANY($1::text[]) " +
      "UNION ALL SELECT 'functionInvocation',id,'execution_active' FROM function_invocations " +
      "WHERE state IN ('queued','running','uncertain') AND " +
      "(request::text LIKE ANY($1::text[]) OR publication::text LIKE ANY($1::text[]) OR settings::text LIKE ANY($1::text[])) " +
      "UNION ALL SELECT 'connectionOperation',id,'connection_busy' FROM connection_operations " +
      "WHERE state IN ('prepared','in_flight','uncertain') AND (executor_id=$2 OR resource_id=ANY($3::uuid[])) " +
      "UNION ALL SELECT 'oauthRelay',id,'authorization_active' FROM oauth_relays WHERE binding_id=$4::uuid AND expires_at>now() " +
      "UNION ALL SELECT 'result',id,'legacy_result_requires_sharing' FROM execution_tasks " +
      "WHERE receipt ? 'sealed' AND EXISTS (SELECT 1 FROM jsonb_array_elements(receipt#>'{sealed,recipients}') r " +
      "WHERE r#>>'{header,kid}'=$4::text) " +
      "UNION ALL SELECT 'principal',id,'key_binding_changed' FROM principals WHERE id=$2 AND NOT EXISTS " +
      "(SELECT 1 FROM principal_key_bindings WHERE principal_id=$2 AND id=$4::uuid AND retired_at IS NULL) " +
      "UNION ALL SELECT 'keyReset',principal_id,'key_reset_pending' FROM challenges " +
      "WHERE principal_id=$2 AND kind='key-reset' AND expires_at>now()",
      [patterns, row.principal_id, items.filter(item => item.kind === 'content').map(item => item.id), row.previous.binding.id], connection);
  }
  private async preparations(id: string, connection: Queryable = this.db.pool) {
    return this.db.all<Prepared>('SELECT * FROM key_rotation_items WHERE rotation_id=$1', [id], connection);
  }
  private summary(row: RotationRow, items: View['items'], blockers: View['blockers'],
    total = row.completed_items, prepared = 0, next: string | null = null): View {
    return { id: row.id, principalId: row.principal_id, state: row.state,
      previous: row.previous, replacement: row.replacement, previousSignature: row.previous_signature,
      createdAt: iso(row.created_at), finishedAt: row.finished_at ? iso(row.finished_at) : null,
      total, prepared: row.state === 'committed' ? total : prepared, blockers, items, next };
  }
  private async canRead(actor: Actor, item: Item) {
    if (item.kind === 'credential' || item.kind === 'environment') return true;
    try {
      if (item.kind === 'content' || item.kind === 'result') await this.custody.read(actor, item.id);
      else await this.custody.resources.authorization.requireResource(actor, await this.custody.resources.get(item.id), 'read');
      return true;
    } catch (error) { if (error instanceof DomainError && error.status === 403) return false; throw error; }
  }
  async get(actor: Actor, principalId: string, id: string, limit = 20, after?: string) {
    await this.authorize(actor, principalId);
    const row = await this.row(principalId, id);
    if (row.state !== 'preparing') return this.summary(row, [], []);
    const items = await this.items(row), prepared = await this.preparations(id);
    const positions = await Promise.all(items.map(async item => {
      const digest = await hash(item.source), saved = prepared.find(value => value.kind === item.kind && value.item_id === item.id);
      return { item, sourceDigest: digest, state: !saved ? 'pending' as const :
        saved.source_digest === digest ? 'prepared' as const : 'stale' as const };
    }));
    const page = positions.filter(({ item }) => !after || item.kind + ':' + item.id > after).slice(0, limit);
    const visible = await Promise.all(page.map(async ({ item, ...value }) => {
      const readable = await this.canRead(actor, item);
      return { kind: item.kind, id: item.id, name: readable ? item.name : null,
        ...value, source: readable ? item.source : null };
    }));
    const last = page.at(-1)?.item, cursor = last ? last.kind + ':' + last.id : null;
    const next = cursor && positions.some(({ item }) => item.kind + ':' + item.id > cursor) ? cursor : null;
    return this.summary(row, visible, await this.blockers(row, items), items.length,
      positions.filter(item => item.state === 'prepared').length, next);
  }

  async prepare(actor: Actor, principalId: string, id: string, kind: Kind, itemId: string,
    input: z.infer<typeof RotationPreparation>) {
    await this.authorize(actor, principalId);
    return this.db.transaction(async connection => {
      const row = await this.row(principalId, id, connection, true);
      if (row.state !== 'preparing') fail(409, 'rotation_finished', 'This key rotation is already finished.');
      await this.checkCurrent(row, connection);
      const item = (await this.items(row, connection, { kind, id: itemId }))[0];
      if (!item) fail(404, 'rotation_item_missing', 'This item is no longer part of this key rotation.');
      if (await hash(item.source) !== input.sourceDigest)
        fail(409, 'changed', 'Read and prepare the current item again.');
      if (kind !== input.payload.kind) fail(400, 'wrong_kind', 'Prepare the selected kind of rotation item.');
      await this.checked(() => this.validate(row, item, input, connection));
      await connection.query(
        'INSERT INTO key_rotation_items(rotation_id,kind,item_id,source_digest,payload,signature) VALUES($1,$2,$3,$4,$5,$6) ' +
        'ON CONFLICT(rotation_id,kind,item_id) DO UPDATE SET source_digest=EXCLUDED.source_digest,payload=EXCLUDED.payload,signature=EXCLUDED.signature',
        [id, kind, itemId, input.sourceDigest, JSON.stringify(input.payload), input.signature]);
      return { ok: true as const };
    });
  }

  private async validate(row: RotationRow, item: Item, input: z.infer<typeof RotationPreparation>, connection: Queryable) {
    const before = row.previous.binding, after = row.replacement.binding, payload = RotationPayload.parse(input.payload);
    await verify(await rotationPreparationProof(row.id, row.principal_id, after.id, item.id, input.sourceDigest, payload),
      input.signature, before.signing, 'key-rotation-preparation');
    if (payload.kind !== item.kind) fail(400, 'wrong_kind', 'Prepare the selected kind of item.');
    switch (payload.kind) {
      case 'content':
      case 'result': {
        const source = item.kind === 'content' ? item.source.content :
          (item.source.receipt as { content: unknown }).content;
        const previous = await verifyContent(ProtectedContent.parse(source));
        const content = await verifyContent(payload.content);
        this.custody.metadata(content);
        if (canonical(content.policy) !== canonical(rotationPolicy(previous.policy, before, after)) ||
          canonical(content.metadata) !== canonical(previous.metadata) ||
          content.materialRevision !== previous.materialRevision + 1 || content.creationRunId !== null ||
          !continuesPolicy(previous.policy, content))
          fail(400, 'invalid_rotation_content', 'Preserve the content metadata and permissions while replacing its keys.');
        const authority = policyAuthority(content);
        const priorAuthority = authority.id === after.id ? before : authority;
        if (authority.id === before.id || content.signerId !== authority.id ||
          !previous.policy.authorities.some(value => canonical(value) === canonical(priorAuthority)))
          fail(403, 'forbidden', 'An existing authority must approve re-encryption.');
        await this.custody.bindings.requireCurrent(priorAuthority, connection);
        const signer = { id: authority.principalId };
        if (payload.kind === 'result') {
          await this.custody.resources.authorization.requirePrincipal(signer, previous.policy.ownerId, 'update', connection);
          await verifyReceipt({ ...(item.source.receipt as object), content } as Parameters<typeof verifyReceipt>[0],
            item.source.intent as Parameters<typeof verifyReceipt>[1]);
        } else {
          await this.custody.resources.authorization.requireResource(signer,
            await this.custody.resources.get(item.id, connection), 'update', connection);
        }
        break;
      }
      case 'credential':
        if (decodeProtectedHeader(WrappedKey.parse(payload.wrappedKey)).sub !== row.principal_id)
          fail(400, 'wrong_principal', 'Wrap the replacement keys for the selected principal.');
        break;
      case 'environment': {
        const previous = SignedEnvironment.parse(item.source.registration);
        const next = await verifyEnvironment(payload.registration);
        const expected = { ...previous.manifest, executor: after, revision: previous.manifest.revision + 1 };
        if (canonical(next.manifest) !== canonical(expected))
          fail(400, 'invalid_rotation_environment', 'Keep the environment configuration while replacing its executor keys.');
        break;
      }
      case 'keyring': {
        const previous = await openKeyring(String(item.source.signature), before);
        const next = await openKeyring(payload.signature, after);
        const expected = { ...previous, signerId: after.id, revision: previous.revision + 1,
          keys: previous.keys.map(entry => entry.binding.id === before.id ? { ...entry, binding: after } : entry) };
        if (canonical(next) !== canonical(expected))
          fail(400, 'invalid_rotation_keyring', 'Preserve the verified identities while replacing the keyring signer.');
        break;
      }
      case 'functionSettings': {
        const previous = await verifyFunctionSettings(item.source.approval as Parameters<typeof verifyFunctionSettings>[0]);
        const next = await verifyFunctionSettings(payload.approval, after);
        const expected = { ...previous, revision: previous.revision + 1, executor: after,
          author: previous.author.id === before.id ? after : previous.author, signature: next.signature };
        if (canonical(next) !== canonical(expected))
          fail(400, 'invalid_rotation_settings', 'Preserve the function execution settings while replacing executor keys.');
        await this.custody.bindings.requireCurrent(next.author.id === after.id ? before : next.author, connection);
        await this.custody.resources.authorization.requireResource({ id: next.author.principalId },
          await this.custody.resources.get(item.id, connection), 'update', connection);
        break;
      }
    }
  }

  private async apply(item: Item, payload: Payload, connection: Queryable) {
    switch (payload.kind) {
      case 'content': {
        await connection.query('UPDATE resource_custody SET content=$2 WHERE resource_id=$1',
          [item.id, JSON.stringify(payload.content)]);
        const resource = await this.custody.resources.get(item.id, connection);
        await this.custody.resources.update(resource,
          { data: { ...resource.data, custodyRevision: payload.content.policy.revision } }, connection);
        break;
      }
      case 'result':
        await connection.query('UPDATE execution_tasks SET receipt=$2 WHERE id=$1',
          [item.id, JSON.stringify({ ...(item.source.receipt as object), content: payload.content })]);
        break;
      case 'credential':
        await connection.query('UPDATE credentials SET private_wrap=$2 WHERE id=$1', [item.id, payload.wrappedKey]);
        break;
      case 'environment': {
        await connection.query('UPDATE executor_environments SET registration=$2 WHERE resource_id=$1',
          [item.id, JSON.stringify(payload.registration)]);
        const resource = await this.custody.resources.get(item.id, connection);
        await this.custody.resources.update(resource,
          { data: { ...resource.data, manifestDigest: await hash(payload.registration.manifest) } }, connection);
        break;
      }
      case 'keyring': {
        const resource = await this.custody.resources.get(item.id, connection);
        await this.custody.resources.update(resource,
          { data: { ...resource.data, signature: payload.signature, revision: keyringClaim(payload.signature).revision } }, connection);
        break;
      }
      case 'functionSettings':
        await connection.query('UPDATE function_settings SET version=$2,approval=$3 WHERE function_id=$1',
          [item.id, payload.approval.revision, JSON.stringify(payload.approval)]);
        break;
    }
  }

  async commit(actor: Actor, principalId: string, id: string) {
    await this.authorize(actor, principalId);
    try {
      return await this.db.transaction(async connection => {
        // Only cutover takes write locks. Reads continue, and preparation never locks the live data.
        // Lock every mutable source while checking the final inventory, including references added after preparation.
        await connection.query("SET LOCAL lock_timeout='3s'");
        await connection.query('SELECT pg_advisory_xact_lock(736023743)');
        await connection.query('LOCK TABLE principals,principal_key_bindings,credentials,resources,resource_custody,' +
          'execution_tasks,executor_environments,function_settings,function_invocations,connection_operations,' +
          'oauth_relays,relations,challenges,key_rotations,key_rotation_items IN SHARE ROW EXCLUSIVE MODE');
        await this.authorize(actor, principalId, connection);
        const row = await this.row(principalId, id, connection, true);
        if (row.state === 'committed') return this.summary(row, [], []);
        if (row.state !== 'preparing') fail(409, 'rotation_finished', 'This key rotation was cancelled.');
        await this.checkCurrent(row, connection);
        const items = await this.items(row, connection), saved = await this.preparations(id, connection);
        const blockers = await this.blockers(row, items, connection);
        if (blockers.length) fail(409, 'rotation_blocked', 'Finish the listed operations before rotating keys.', { blockers });
        const prepared: Array<{ item: Item; value: Prepared }> = [];
        for (const item of items) {
          const value = saved.find(value => value.kind === item.kind && value.item_id === item.id);
          if (!value || value.source_digest !== await hash(item.source))
            fail(409, 'rotation_not_ready', 'Prepare every current item before committing the rotation.',
              { kind: item.kind, id: item.id, reason: value ? 'changed' : 'missing' });
          const input = { sourceDigest: value.source_digest, payload: value.payload, signature: value.signature };
          await this.checked(() => this.validate(row, item, input, connection));
          prepared.push({ item, value });
        }
        const before = row.previous.binding, after = row.replacement.binding;
        await connection.query('UPDATE principal_key_bindings SET retired_at=now() WHERE id=$1', [before.id]);
        await connection.query('INSERT INTO principal_key_bindings(id,principal_id,binding,signature) VALUES($1,$2,$3,$4)',
          [after.id, principalId, JSON.stringify(after), row.replacement.signature]);
        await connection.query('UPDATE principals SET public_key=$2 WHERE id=$1',
          [principalId, JSON.stringify(after.encryption)]);
        for (const { item, value } of prepared) await this.apply(item, value.payload, connection);
        const remaining = (await this.items(row, connection)).filter(item => item.kind !== 'credential');
        if (remaining.length) fail(409, 'rotation_not_ready', 'Prepare every reference to the previous keys.');
        const completed = required(await this.db.one<RotationRow>(
          "UPDATE key_rotations SET state='committed',completed_items=$2,finished_at=now() WHERE id=$1 RETURNING *",
          [id, items.length], connection));
        await connection.query('DELETE FROM key_rotation_items WHERE rotation_id=$1', [id]);
        await this.custody.resources.audit.record(principalId, actor.id, 'principal.commitKeyRotation', id,
          { generation: after.generation, items: items.length }, connection);
        return this.summary(completed, [], []);
      });
    } catch (error) {
      const code = error && typeof error === 'object' && 'code' in error ? error.code : null;
      if (code === '40P01' || code === '55P03')
        fail(409, 'rotation_busy', 'An update is in progress. Retry the key rotation.');
      throw error;
    }
  }

  async cancel(actor: Actor, principalId: string, id: string) {
    await this.authorize(actor, principalId);
    return this.db.transaction(async connection => {
      const row = await this.row(principalId, id, connection, true);
      if (row.state === 'committed') fail(409, 'rotation_finished', 'A committed key rotation cannot be cancelled.');
      if (row.state === 'cancelled') return { ok: true as const };
      await connection.query("UPDATE key_rotations SET state='cancelled',finished_at=now() WHERE id=$1", [id]);
      await connection.query('DELETE FROM key_rotation_items WHERE rotation_id=$1', [id]);
      await this.custody.resources.audit.record(principalId, actor.id, 'principal.cancelKeyRotation', id, {}, connection);
      return { ok: true as const };
    });
  }
}
