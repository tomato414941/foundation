import type { Database, Queryable } from './database.js';
import type { Authorization, Actor } from './authorization.js';
import type { ResourceRow } from './resources.js';
import type { PublicEncryptionKey, SealedContent } from '../shared/contracts.js';
import { base64url, encode } from '../shared/encryption.js';
import { fail } from './errors.js';

export type KeyUpdates = Record<string, { version: number; sealed: SealedContent }>;

export class KeySharing {
  constructor(readonly db: Database, readonly authorization: Authorization, readonly serverId: string) {}

  async plan(actor: Actor, target: string, subject: string, relation: 'owner' | 'member', connection: Queryable = this.db.pool) {
    const descendants = await this.authorization.standsAs(target, connection);
    const rows = await this.db.all<ResourceRow>("SELECT * FROM resources WHERE kind='secret' AND owner_id=ANY($1::uuid[]) ORDER BY id", [descendants], connection);
    const items = [];
    for (const row of rows) {
      const recipients = await this.db.all<{ id: string; name: string; public_key: PublicEncryptionKey }>(`WITH RECURSIVE edges(subject_id,principal_id) AS (
        SELECT subject_id,principal_id FROM relations WHERE relation IN ('owner','member') AND NOT ($3='owner' AND relation='owner' AND principal_id=$1)
        UNION SELECT $2::uuid,$1::uuid
      ), readers(id) AS (
        SELECT $4::uuid UNION SELECT principal_id FROM grants WHERE resource_id=$5 AND 'reveal'=ANY(actions)
        UNION SELECT e.subject_id FROM edges e JOIN readers r ON e.principal_id=r.id
      ) SELECT p.id,p.name,p.public_key FROM principals p WHERE p.public_key IS NOT NULL AND (
        p.id IN (SELECT id FROM readers) OR (p.id=$6 AND EXISTS(SELECT 1 FROM grants WHERE resource_id=$5 AND principal_id=$6 AND 'use'=ANY(actions)))
      ) ORDER BY p.id`, [target, subject, relation, row.owner_id, row.id, this.serverId], connection);
      if (!recipients.some(recipient => recipient.id !== this.serverId)) fail(409, 'encryption_key_required', 'The new owner or member needs an encryption key.');
      const current = new Set(row.sealed!.recipients.map(recipient => recipient.header.kid));
      if (current.size === recipients.length && recipients.every(recipient => current.has(recipient.id))) continue;
      await this.authorization.requireResource(actor, row, 'reveal', connection);
      await this.authorization.requireResource(actor, row, 'update', connection);
      items.push({ id: row.id, name: row.name, version: row.version, sealed: row.sealed!, recipients: recipients.map(recipient => ({ id: recipient.id, name: recipient.name, publicKey: recipient.public_key })) });
    }
    return { items, next: null };
  }

  async apply(actor: Actor, target: string, subject: string, relation: 'owner' | 'member', updates: KeyUpdates, connection: Queryable) {
    const plan = await this.plan(actor, target, subject, relation, connection);
    for (const item of plan.items) {
      const update = updates[item.id];
      if (!update) fail(409, 'rekey_required', 'Encrypt existing secrets for the new owner or member.');
      if (update.version !== item.version) fail(409, 'changed', 'A secret changed. Reload before sharing.');
      const addressed = new Set(update.sealed.recipients.map(recipient => recipient.header.kid));
      if (update.sealed.aad !== base64url(encode('resource:' + item.id)) || addressed.size !== item.recipients.length || update.sealed.recipients.length !== addressed.size || item.recipients.some(recipient => !addressed.has(recipient.id))) fail(400, 'missing_recipient', 'Encrypt the secret for the specified recipients.');
      await connection.query("UPDATE resources SET sealed=$2,data=jsonb_set(data,'{recipients}',$3::jsonb),version=version+1,updated_at=now() WHERE id=$1", [item.id, JSON.stringify(update.sealed), JSON.stringify([...addressed])]);
    }
  }
}
