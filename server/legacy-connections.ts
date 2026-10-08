import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { Actor } from './authorization.js';
import type { Queryable } from './database.js';
import type { Custody, ProtectedWrite } from './custody.js';
import type { Vault } from './vault.js';
import type { ResourceRow } from './resources.js';
import { AccessPolicy } from '../shared/custody.js';
import { canonical, hash } from '../shared/authority.js';
import type { BoundKeys } from '../shared/authority.js';
import { MethodDefinition } from '../shared/contracts.js';
import type { JsonValue } from '../shared/contracts.js';
import { AppMaterial, ConnectionMaterial, connectionMetadata, requiresApp } from '../shared/connections.js';
import { encode, seal } from '../shared/encryption.js';
import { fail, required } from './errors.js';

const LegacyState = z.object({ formatVersion: z.literal(2), methodId: z.string().min(1), method: MethodDefinition,
  app: z.object({ clientId: z.string(), clientSecret: z.string().optional(), fields: z.record(z.string(), z.string()),
    version: z.number().optional() }).strict(),
  oauth: ConnectionMaterial.shape.oauth, fields: ConnectionMaterial.shape.fields, role: ConnectionMaterial.shape.role,
  appVersion: z.number().optional(),
}).strict();
function applicationId(id: string) {
  const hex = createHash('sha256').update('Foundation legacy OAuth application:' + id).digest('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-5${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

// The old vault already holds these credentials. Only an authorized owner can
// receive their conversion, encrypted to their unchanged key, and sign custody.
export class LegacyConnections {
  constructor(readonly custody: Custody, readonly vault: Vault) {}

  async pending(actor: Actor) {
    const { resources } = this.custody;
    await resources.authorization.active(actor);
    if (actor.requestId) fail(403, 'forbidden', 'Sign in as the owner to migrate connections.');
    const owners = await resources.authorization.standsAs(actor.id);
    const rows = await resources.db.all<{ id: string }>(
      `SELECT r.id FROM resources r WHERE r.kind='connection' AND r.owner_id=ANY($1::uuid[])
       AND r.private_data IS NOT NULL AND NOT EXISTS(SELECT 1 FROM resource_custody c WHERE c.resource_id=r.id)
       ORDER BY r.id`, [owners]);
    return { items: rows.map(row => row.id), next: null };
  }

  async plan(actor: Actor, id: string, connection: Queryable = this.custody.resources.db.pool) {
    const { resources, bindings } = this.custody, row = await resources.get(id, connection);
    await resources.authorization.requireResource(actor, row, 'reveal', connection);
    await resources.authorization.requireResource(actor, row, 'update', connection);
    if (actor.requestId || !await resources.authorization.stands(actor.id, row.owner_id, connection))
      fail(403, 'forbidden', 'Only an owner or member can migrate this connection.');
    if (row.kind !== 'connection')
      fail(409, 'migration_unavailable', 'This item does not have readable legacy connection material.');
    if (await resources.db.one('SELECT 1 FROM resource_custody WHERE resource_id=$1', [id], connection))
      fail(409, 'already_migrated', 'This connection is already migrated.');
    if (!row.private_data)
      fail(409, 'migration_unavailable', 'This item does not have readable legacy connection material.');
    const old = LegacyState.safeParse(await this.vault.decrypt(row.private_data, 'resource:' + id));
    if (!old.success || old.data.methodId !== row.data.methodId || !['ready', 'reconnect'].includes(String(row.data.state)))
      fail(409, 'reconnect_required', 'Review this connection before migrating its material.');
    const state = old.data, signed = new Map<string, Awaited<ReturnType<typeof bindings.current>>>();
    const readers = new Map<string, BoundKeys>();
    for (const reader of await resources.recipients(row.owner_id, connection)) {
      const current = await bindings.current(reader.id, connection);
      signed.set(reader.id, current); readers.set(reader.id, current.binding);
    }
    for (const recipient of row.sealed?.recipients ?? []) {
      const principalId = recipient.header.kid;
      if (readers.has(principalId) || !await resources.authorization.resource({ id: principalId }, row, 'reveal', connection)) continue;
      const current = await bindings.current(principalId, connection);
      signed.set(principalId, current); readers.set(principalId, current.binding);
    }
    if (!readers.has(actor.id)) fail(409, 'key_unavailable', 'Keep the migrating owner as a reader.');
    const authorities: BoundKeys[] = [];
    for (const reader of await resources.recipients(row.owner_id, connection)) authorities.push(readers.get(reader.id)!);
    const agents: BoundKeys[] = [];
    for (const candidate of await resources.db.all<{ id: string }>('SELECT id FROM principals ORDER BY id', [], connection)) {
      if (readers.has(candidate.id) || !await resources.authorization.resource({ id: candidate.id }, row, 'use', connection)) continue;
      const current = await bindings.current(candidate.id, connection);
      signed.set(candidate.id, current); agents.push(current.binding);
    }
    const ordered = <T extends { id: string }>(values: Iterable<T>) => [...values].sort((a, b) => a.id.localeCompare(b.id));
    const policy = (kind: 'connection' | 'app', resourceId: string) => AccessPolicy.parse({
      format: 1, id: resourceId, origin: this.custody.origin, ownerId: row.owner_id, kind, revision: 1,
      readers: ordered(readers.values()), authorities: ordered(authorities), producers: [],
      grants: agents.map(binding => ({ actor: binding, executor: binding,
        operations: kind === 'app' ? ['refresh', 'revoke'] : ['http', 'command', 'function', 'refresh', 'revoke'],
        callerProgram: true, expiresAt: '9999-12-31T23:59:59.999Z' })),
    });
    const appId = requiresApp(state.method) ? applicationId(id) : null;
    if (appId && await resources.db.one('SELECT 1 FROM resources WHERE id=$1', [appId], connection))
      fail(409, 'changed', 'The migration application destination is already occupied.');
    const material = ConnectionMaterial.parse(JSON.parse(canonical({ format: 1, methodId: state.methodId, method: state.method,
      generation: id, appId, appGeneration: appId,
      ...(row.data.state === 'reconnect' ? { state: 'reconnect' } : {}),
      ...(state.oauth ? { oauth: state.oauth } : {}), ...(state.fields ? { fields: state.fields } : {}),
      ...(state.role ? { role: state.role } : {}),
    })));
    const app = appId ? AppMaterial.parse({ format: 1, methodId: state.methodId, generation: appId,
      clientId: state.app.clientId, ...(state.app.clientSecret ? { clientSecret: state.app.clientSecret } : {}), fields: state.app.fields }) : null;
    const item = async (resourceId: string, name: string, kind: 'connection' | 'app', material: unknown, metadata: Record<string, JsonValue>) => {
      const bytes = encode(canonical(material));
      try {
        return { id: resourceId, name, policy: policy(kind, resourceId), metadata, materialHash: await hash(material),
          sealed: await seal(bytes, [{ id: actor.id, publicKey: readers.get(actor.id)!.encryption }], 'resource:' + resourceId) };
      } finally { bytes.fill(0); }
    };
    const migrated = await item(id, row.name, 'connection', material, await connectionMetadata(material));
    const application = app ? await item(appId!, `${state.method.name} · ${row.name}`.slice(0, 180) + ' · ' + id.slice(0, 8),
      'app', app, { methodId: app.methodId, clientId: app.clientId, generation: app.generation }) : null;
    const summary = (value: typeof migrated) => ({ id: value.id, name: value.name, policy: value.policy,
      metadata: value.metadata, materialHash: value.materialHash });
    const digest = await hash({ legacy: { id: row.id, ownerId: row.owner_id, name: row.name, version: row.version,
      data: row.data, sealed: row.sealed, privateData: row.private_data },
      connection: summary(migrated), app: application ? summary(application) : null });
    return { id, version: row.version, digest, connection: migrated, app: application, bindings: [...signed.values()] };
  }

  async complete(actor: Actor, input: { digest: string; connection: ProtectedWrite; app: ProtectedWrite | null }) {
    const { resources } = this.custody;
    return resources.db.transaction(async connection => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      const id = input.connection.content.policy.id;
      const row = required(await resources.db.one<ResourceRow>('SELECT * FROM resources WHERE id=$1 FOR UPDATE', [id], connection));
      const existing = await resources.db.one<{ content: unknown }>('SELECT content FROM resource_custody WHERE resource_id=$1', [id], connection);
      if (existing) {
        await resources.authorization.requireResource(actor, row, 'reveal', connection);
        if (canonical(existing.content) === canonical(input.connection.content)) return row;
        fail(409, 'changed', 'This connection has already been migrated.');
      }
      const plan = await this.plan(actor, id, connection);
      const matches = (expected: typeof plan.connection, supplied: ProtectedWrite) =>
        supplied.name === expected.name && supplied.content.materialRevision === 1 &&
        canonical(supplied.content.policy) === canonical(expected.policy) &&
        canonical(supplied.content.metadata) === canonical(expected.metadata);
      if (input.digest !== plan.digest || input.connection.version !== plan.version || !matches(plan.connection, input.connection) ||
        Boolean(input.app) !== Boolean(plan.app) || (plan.app && (!input.app || input.app.version !== undefined || !matches(plan.app, input.app))))
        fail(409, 'changed', 'Keep the existing material, recipients and permissions during migration.');
      if (input.app) await this.custody.put(actor, input.app, connection);
      const migrated = await this.custody.put(actor, input.connection, connection);
      await resources.audit.record(row.owner_id, actor.id, 'connection.migrate', id,
        { previousVersion: row.version, appId: plan.app?.id ?? null }, connection);
      return migrated;
    });
  }
}
