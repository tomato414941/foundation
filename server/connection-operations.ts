import type { Actor } from './authorization.js';
import type { Custody } from './custody.js';
import type { Queryable } from './database.js';
import { canonical } from '../shared/digest.js';
import { SealedItem, sealedFor } from '../shared/custody.js';
import type { SealedItemValue } from '../shared/custody.js';
import { fail, required } from './errors.js';

export interface ConnectionOperation {
  id: string;
  resource_id: string;
  renewer_id: string;
  expected_revision: number;
  state: 'prepared' | 'in_flight' | 'committed' | 'uncertain' | 'aborted';
  fence: string;
  result: SealedItemValue | null;
}

export class ConnectionOperations {
  constructor(readonly custody: Custody) {}
  get db() { return this.custody.resources.db; }

  // A connection is renewed by whoever it is sealed for, each on its own device, while they may open it.
  private async allowed(actor: Actor, resourceId: string, connection: Queryable = this.db.pool) {
    await this.custody.resources.authorization.active(actor, connection);
    const row = await this.custody.resources.get(resourceId, connection);
    if (row.kind !== 'connection' || !await this.custody.resources.authorization.can(actor, row, 'reveal', connection))
      fail(403, 'forbidden', 'Only one who may open this connection can renew it.');
    const content = await this.custody.get(resourceId, connection), own = (await this.custody.keyed([actor.id], connection))[0];
    if (!own || !await sealedFor(content, own.publicKey))
      fail(403, 'forbidden', 'Only one this connection is sealed for can renew it.');
    return { row, content };
  }

  async prepare(actor: Actor, id: string, resourceId: string, expectedRevision: number) {
    return this.db.transaction(async connection => {
      await connection.query('SELECT id FROM resources WHERE id=$1 FOR UPDATE', [resourceId]);
      const { content } = await this.allowed(actor, resourceId, connection);
      const existing = await this.db.one<ConnectionOperation>('SELECT * FROM connection_operations WHERE id=$1', [id], connection);
      if (existing) {
        if (existing.resource_id !== resourceId || existing.renewer_id !== actor.id || existing.expected_revision !== expectedRevision)
          fail(409, 'operation_conflict', 'Use a new operation ID for another token update.');
        return existing;
      }
      if (content.revision !== expectedRevision)
        fail(409, 'changed', 'Read the current connection before refreshing it.');
      const active = await this.db.one<ConnectionOperation>(
        "SELECT * FROM connection_operations WHERE resource_id=$1 AND state IN ('prepared','in_flight','uncertain')", [resourceId], connection,
      );
      if (active) fail(409, active.state === 'uncertain' ? 'connection_uncertain' : 'connection_busy',
        active.state === 'uncertain' ? 'Resolve the previous token update or reconnect this service.' : 'Another device is updating this connection.');
      return required(await this.db.one<ConnectionOperation>(
        "INSERT INTO connection_operations(id,resource_id,renewer_id,expected_revision,state) VALUES($1,$2,$3,$4,'prepared') RETURNING *",
        [id, resourceId, actor.id, expectedRevision], connection,
      ));
    });
  }

  private async operation(actor: Actor, id: string, fence: string, connection: Queryable = this.db.pool) {
    await this.custody.resources.authorization.active(actor, connection);
    const operation = required(await this.db.one<ConnectionOperation>(
      'SELECT * FROM connection_operations WHERE id=$1 AND fence=$2::bigint', [id, fence], connection,
    ));
    if (operation.renewer_id !== actor.id) fail(403, 'forbidden', 'Use the identity that started this update.');
    return operation;
  }

  async dispatch(actor: Actor, id: string, fence: string) {
    const operation = await this.operation(actor, id, fence);
    await this.allowed(actor, operation.resource_id);
    const updated = await this.db.one<ConnectionOperation>(
      "UPDATE connection_operations SET state='in_flight',updated_at=now() WHERE id=$1 AND fence=$2::bigint AND state='prepared' RETURNING *",
      [id, fence],
    );
    if (!updated) fail(409, 'connection_uncertain', 'A dispatched token update must be reconciled before another request.');
    return updated;
  }

  async commit(actor: Actor, id: string, fence: string, input: SealedItemValue) {
    const content = SealedItem.parse(input);
    this.custody.metadata('connection', content);
    return this.db.transaction(async connection => {
      const operation = await this.operation(actor, id, fence, connection);
      await connection.query('SELECT id FROM resources WHERE id=$1 FOR UPDATE', [operation.resource_id]);
      const locked = await this.operation(actor, id, fence, connection);
      if (locked.state === 'committed') {
        if (canonical(locked.result) !== canonical(content))
          fail(409, 'operation_conflict', 'This update already has a different result.');
        return locked.result!;
      }
      if (!['in_flight', 'uncertain'].includes(locked.state))
        fail(409, 'invalid_operation', 'Start the token update before committing its result.');
      const { row: resource, content: previous } = await this.allowed(actor, operation.resource_id, connection);
      if (previous.revision !== operation.expected_revision || content.revision !== operation.expected_revision + 1)
        fail(409, 'changed', 'A token update must replace this revision of the connection.');
      await this.custody.requireSealedFor(content, await this.custody.recipients(resource, connection));
      await connection.query('UPDATE resource_custody SET content=$2 WHERE resource_id=$1',
        [operation.resource_id, JSON.stringify(content)]);
      await this.custody.resources.update(resource, {
        data: { ...resource.data, ...content.metadata, state: 'ready' },
      }, connection);
      await connection.query(
        "UPDATE connection_operations SET state='committed',result=$3,updated_at=now() WHERE id=$1 AND fence=$2::bigint",
        [id, fence, JSON.stringify(content)],
      );
      await this.custody.resources.audit.record(resource.owner_id, actor.id, 'connection.renew', resource.id,
        { operationId: id, revision: content.revision }, connection);
      return content;
    });
  }

  async uncertain(actor: Actor, id: string, fence: string) {
    const operation = await this.operation(actor, id, fence);
    await this.db.transaction(async connection => {
      await connection.query('SELECT id FROM resources WHERE id=$1 FOR UPDATE', [operation.resource_id]);
      const changed = await connection.query(
        "UPDATE connection_operations SET state='uncertain',updated_at=now() WHERE id=$1 AND fence=$2::bigint AND state='in_flight' RETURNING id",
        [id, fence],
      );
      if (changed.rowCount) await connection.query(
        `UPDATE resources SET data=jsonb_set(data,'{state}','"uncertain"'),version=version+1 WHERE id=$1`,
        [operation.resource_id],
      );
    });
  }

  async abort(actor: Actor, id: string, fence: string) {
    await this.operation(actor, id, fence);
    const updated = await this.db.one<ConnectionOperation>(
      "UPDATE connection_operations SET state='aborted',updated_at=now() WHERE id=$1 AND fence=$2::bigint AND state='prepared' RETURNING *",
      [id, fence],
    );
    if (!updated) fail(409, 'connection_uncertain', 'Check the provider state before resolving a dispatched update.');
    return updated;
  }

  async state(actor: Actor, resourceId: string) {
    await this.allowed(actor, resourceId, this.db.pool);
    return await this.db.one<ConnectionOperation>(
      "SELECT * FROM connection_operations WHERE resource_id=$1 AND state IN ('prepared','in_flight','uncertain')", [resourceId],
    ) ?? null;
  }

  async recover() {
    await this.db.pool.query(
      "UPDATE connection_operations SET state='aborted',updated_at=now() WHERE state='prepared' AND updated_at<now()-interval '10 minutes'",
    );
    const rows = await this.db.all<{ id: string; resource_id: string }>(
      "SELECT id,resource_id FROM connection_operations WHERE state='in_flight' AND updated_at<now()-interval '2 minutes'",
    );
    for (const row of rows) await this.db.transaction(async connection => {
      await connection.query('SELECT id FROM resources WHERE id=$1 FOR UPDATE', [row.resource_id]);
      const changed = await connection.query(
        "UPDATE connection_operations SET state='uncertain',updated_at=now() WHERE id=$1 AND state='in_flight' AND updated_at<now()-interval '2 minutes' RETURNING id",
        [row.id],
      );
      if (changed.rowCount) await connection.query(
        `UPDATE resources SET data=jsonb_set(data,'{state}','"uncertain"'),version=version+1 WHERE id=$1`, [row.resource_id],
      );
    });
  }
}
