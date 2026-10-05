import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { JsonValue } from '../shared/contracts.js';

export class Audit {
  constructor(private readonly db: Database) {}
  async record(
    ownerId: string,
    actorId: string | null,
    action: string,
    targetId: string | null,
    details: Record<string, JsonValue> = {},
    connection: Queryable = this.db.pool,
  ) {
    await connection.query(
      'INSERT INTO audit_log(owner_id,actor_id,action,target_id,details) VALUES($1,$2,$3,$4,$5)',
      [ownerId, actorId, action, targetId, JSON.stringify(details)],
    );
  }
  async list(ownerId: string, limit = 100, after?: string) {
    const rows = await this.db.all<{
      id: string;
      actor_id: string | null;
      action: string;
      target_id: string | null;
      details: Record<string, JsonValue>;
      created_at: Date;
    }>(
      'SELECT * FROM audit_log WHERE owner_id=$1 AND ($2::bigint IS NULL OR id<$2) ORDER BY id DESC LIMIT $3',
      [ownerId, after ?? null, limit + 1],
    );
    const selected = rows.slice(0, limit);
    return {
      items: selected.map((row) => ({
        id: row.id,
        actorId: row.actor_id,
        action: row.action,
        targetId: row.target_id,
        details: row.details,
        createdAt: iso(row.created_at),
      })),
      next: rows.length > limit ? selected.at(-1)!.id : null,
    };
  }
}
