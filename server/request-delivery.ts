import { randomUUID } from 'node:crypto';
import type { Queryable } from './database.js';

export async function deliverExecution(connection: Queryable, input: {
  executionId: string; fromId: string; toId: string | null; message: string;
  purpose: 'input' | 'approval'; expiresAt: Date;
}) {
  const result = await connection.query<{ id: string }>(`INSERT INTO requests(id,execution_id,from_id,to_id,message,purpose,expires_at)
    VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(execution_id) WHERE state='pending'
    DO UPDATE SET execution_id=excluded.execution_id RETURNING id`,
  [randomUUID(), input.executionId, input.fromId, input.toId, input.message, input.purpose, input.expiresAt]);
  return result.rows[0]!.id;
}
