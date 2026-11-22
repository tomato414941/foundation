import type { z } from 'zod';
import { RoleOf } from '../shared/contracts.js';
import { sealedFor } from '../shared/custody.js';
import { canonical } from '../shared/digest.js';
import { ConnectionSharePermission } from '../shared/connection-sharing.js';
import type { ConnectionShare } from '../shared/connection-sharing.js';
import type { Actor, Change } from './authorization.js';
import { principal } from './authorization.js';
import type { Custody } from './custody.js';
import type { Queryable } from './database.js';
import { fail } from './errors.js';
import type { ResourceRow } from './resources.js';

type Permission = z.infer<typeof ConnectionSharePermission>;
const shareRoles = ConnectionSharePermission.options.map(permission => RoleOf[permission]);

export class ConnectionSharing {
  constructor(readonly custody: Custody) {}

  private async protection(row: ResourceRow, subjectId: string, change: Change, connection: Queryable) {
    if (row.data.state === 'reconnect')
      fail(409, 'reconnect_required', 'Reconnect this service before sharing it.');
    if (row.data.state === 'uncertain')
      fail(409, 'connection_uncertain', 'Resolve the token update before sharing this connection.');

    const { resources } = this.custody;
    const holders = new Set(await resources.authorization.holders(principal(subjectId), 'stands', connection));
    const recipients = await this.custody.recipients(row, connection, change);
    const sharedWith = recipients.filter(recipient => holders.has(recipient.id));
    if (!sharedWith.length)
      fail(409, 'share_recipient_key_required', 'The recipient needs an encryption key before they can use this connection.');

    // Using a connection made with a private application requires opening that application too.
    const appId = row.data.appId;
    if (typeof appId === 'string') {
      const app = await resources.get(appId, connection);
      const allowed = new Set((await this.custody.recipients(app, connection)).map(recipient => recipient.id));
      const content = await this.custody.get(app.id, connection);
      const access = await Promise.all(sharedWith.map(async ({ id, publicKey }) =>
        allowed.has(id) && await sealedFor(content, publicKey)));
      if (!access.every(Boolean))
        fail(409, 'share_application_required', 'Give the recipient access to the connection application first.');
    }

    const previous = await this.custody.get(row.id, connection);
    if ((await Promise.all(sharedWith.map(recipient => sealedFor(previous, recipient.publicKey)))).every(Boolean)) return null;
    return { item: { id: row.id, name: row.name, version: row.version, recipients }, metadata: previous.metadata };
  }

  private async plan(actor: Actor, id: string, subjectId: string, permission: Permission | null, connection: Queryable) {
    const { resources, relations } = this.custody;
    const row = await resources.get(id, connection);
    await resources.authorization.requireResource(actor, row, 'share', connection);
    if (row.kind !== 'connection') fail(400, 'wrong_kind', 'Choose a connection.');
    const line = (relation: string) => ({ objectId: id, subjectId, relation });
    const desired = permission && RoleOf[permission];
    if (desired) await relations.requireDraw(actor, line(desired), connection);
    const current = (await resources.db.all<{ relation: string }>(
      'SELECT relation FROM relations WHERE resource_id=$1 AND subject_id=$2 AND relation=ANY($3::text[])',
      [id, subjectId, shareRoles], connection)).map(entry => entry.relation);
    const add = desired && !current.includes(desired) ? [line(desired)] : [];
    const remove = current.filter(relation => relation !== desired).map(line);
    const protection = permission === 'update' || permission === 'reveal'
      ? await this.protection(row, subjectId, { add, remove }, connection) : null;
    return { row, add, remove, protection };
  }

  async recipients(actor: Actor, id: string, subjectId: string, permission: Permission) {
    return (await this.plan(actor, id, subjectId, permission, this.custody.resources.db.pool)).protection?.item ?? null;
  }

  async save(actor: Actor, id: string, subjectId: string, input: z.infer<typeof ConnectionShare>) {
    const { resources, relations } = this.custody;
    return resources.db.transaction(async connection => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      await connection.query('SELECT id FROM resources WHERE id=$1 FOR UPDATE', [id]);
      const { row, add, remove, protection } = await this.plan(actor, id, subjectId, input.permission, connection);
      if (protection) {
        const update = input.protection;
        if (!update) fail(409, 'rekey_required', 'Seal this connection for the recipients listed for this share before saving it.');
        if (canonical(update.content.metadata) !== canonical(protection.metadata))
          fail(409, 'changed', 'Use the current connection to change access.');
        await this.custody.put(actor, { id: row.id, name: row.name, kind: 'connection', ownerId: row.owner_id,
          ...update }, connection, protection.item.recipients);
      }
      for (const line of add) await relations.draw(actor, line, connection);
      for (const line of remove) await relations.erase(actor, line, connection);
      return { ok: true as const };
    });
  }
}
