import type { Actor } from './authorization.js';
import type { Queryable } from './database.js';
import type { Custody, ProtectedWrite } from './custody.js';
import type { ResourceRow } from './resources.js';
import { AccessPolicy } from '../shared/custody.js';
import { canonical } from '../shared/authority.js';
import type { BoundKeys } from '../shared/authority.js';
import { unbase64url } from '../shared/encryption.js';
import { fail, required } from './errors.js';

// Only the old ciphertext is delivered. Its owner decrypts and signs the new
// policy on their device; this service never receives plaintext or private keys.
export class LegacySecrets {
  constructor(readonly custody: Custody) {}

  async plan(actor: Actor, id: string, connection: Queryable = this.custody.resources.db.pool) {
    const { resources, bindings } = this.custody;
    const row = await resources.get(id, connection);
    await resources.authorization.requireResource(actor, row, 'reveal', connection);
    await resources.authorization.requireResource(actor, row, 'update', connection);
    if (!await resources.authorization.stands(actor.id, row.owner_id, connection))
      fail(403, 'forbidden', 'Only an owner or member can migrate this item.');
    if (row.kind !== 'secret')
      fail(409, 'migration_unavailable', 'This item does not have a readable legacy secret.');
    if (await resources.db.one('SELECT 1 FROM resource_custody WHERE resource_id=$1', [id], connection))
      fail(409, 'already_migrated', 'This secret is already migrated.');
    if (!row.sealed)
      fail(409, 'migration_unavailable', 'This item does not have a readable legacy secret.');
    if (!row.sealed.recipients.some(recipient => recipient.header.kid === actor.id))
      fail(409, 'key_unavailable', 'Use a device holding a recipient key for this secret.');

    const ownerReaders = await resources.recipients(row.owner_id, connection);
    const readers = new Map<string, BoundKeys>(), authorities = new Map<string, BoundKeys>();
    const signed = new Map<string, Awaited<ReturnType<typeof bindings.current>>>();
    for (const reader of ownerReaders) {
      const current = await bindings.current(reader.id, connection);
      signed.set(reader.id, current);
      readers.set(reader.id, current.binding);
      authorities.set(reader.id, current.binding);
    }
    const oldServer = await resources.db.one<{ value: { id: string } }>(
      "SELECT value FROM system_settings WHERE name='server-identity'", [], connection);
    for (const recipient of row.sealed.recipients) {
      const id = recipient.header.kid;
      if (id === oldServer?.value.id || readers.has(id)) continue;
      if (!await resources.authorization.resource({ id }, row, 'reveal', connection)) continue;
      const current = await bindings.current(id, connection);
      signed.set(id, current); readers.set(id, current.binding);
    }
    if (!readers.has(actor.id)) fail(409, 'key_unavailable', 'Keep the migrating identity as a reader.');

    const grants = [];
    const allowedUse = row.data.allowUse === true ||
      row.sealed.recipients.some(recipient => recipient.header.kid === oldServer?.value.id);
    if (allowedUse) {
      const candidates = await resources.db.all<{ principal_id: string }>(
        'SELECT principal_id FROM principal_key_bindings WHERE retired_at IS NULL ORDER BY principal_id', [], connection);
      for (const candidate of candidates) {
        const id = candidate.principal_id;
        if (readers.has(id) || id === oldServer?.value.id ||
          !await resources.authorization.resource({ id }, row, 'use', connection)) continue;
        const current = await bindings.current(id, connection);
        signed.set(id, current);
        // Legacy use allowed arbitrary programs. Preserve that permission for
        // local execution, without turning the executor into a reveal reader.
        grants.push({ actor: current.binding, executor: current.binding,
          operations: ['http', 'command', 'function', 'refresh', 'revoke'], callerProgram: true,
          expiresAt: '9999-12-31T23:59:59.999Z' });
      }
    }
    const byId = <T extends { id: string }>(values: Iterable<T>) => [...values].sort((a, b) => a.id.localeCompare(b.id));
    const policy = AccessPolicy.parse({ format: 1, id, origin: this.custody.origin, ownerId: row.owner_id,
      kind: 'secret', revision: 1, readers: byId(readers.values()), authorities: byId(authorities.values()),
      grants, producers: [] });
    return { id, name: row.name, version: row.version, sealed: row.sealed, policy,
      bindings: [...signed.values()] };
  }

  async pending(actor: Actor) {
    await this.custody.resources.authorization.active(actor);
    if (actor.requestId) fail(403, 'forbidden', 'Sign in as the owner to migrate secrets.');
    const owners = await this.custody.resources.authorization.standsAs(actor.id);
    const rows = await this.custody.resources.db.all<ResourceRow>(
      `SELECT r.* FROM resources r WHERE r.kind='secret' AND r.owner_id=ANY($1::uuid[])
       AND r.sealed IS NOT NULL AND NOT EXISTS(SELECT 1 FROM resource_custody c WHERE c.resource_id=r.id)
       ORDER BY r.id`, [owners]);
    const items: string[] = [];
    for (const row of rows) {
      if (row.sealed!.recipients.some(recipient => recipient.header.kid === actor.id)) items.push(row.id);
    }
    return { items, next: null };
  }

  async complete(actor: Actor, input: ProtectedWrite) {
    const { resources } = this.custody;
    return resources.db.transaction(async connection => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      const current = required(await resources.db.one<ResourceRow>(
        'SELECT * FROM resources WHERE id=$1 FOR UPDATE', [input.content.policy.id], connection));
      const existing = await resources.db.one<{ content: unknown }>(
        'SELECT content FROM resource_custody WHERE resource_id=$1', [current.id], connection);
      if (existing) {
        await resources.authorization.requireResource(actor, current, 'reveal', connection);
        if (canonical(existing.content) === canonical(input.content)) return current;
        fail(409, 'changed', 'This secret was already migrated by another device.');
      }
      const plan = await this.plan(actor, current.id, connection);
      if (input.version !== plan.version || input.name !== plan.name ||
        canonical(input.content.policy) !== canonical(plan.policy) || input.content.materialRevision !== 1 ||
        input.content.metadata.bytes !== unbase64url(plan.sealed.ciphertext).byteLength)
        fail(409, 'changed', 'Keep the current recipients and permissions during migration.');
      const row = await this.custody.put(actor, input, connection);
      await resources.audit.record(row.owner_id, actor.id, 'secret.migrate', row.id,
        { previousVersion: plan.version }, connection);
      return row;
    });
  }
}
