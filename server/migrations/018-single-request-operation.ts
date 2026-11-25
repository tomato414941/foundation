import { randomUUID } from 'node:crypto';
import type { RequestedOperation } from '../../shared/contracts.js';
import type { Actor } from '../authorization.js';
import type { Queryable } from '../database.js';
import type { Vault } from '../vault.js';

interface PreviousRequest { creatorActor: Actor; operations: RequestedOperation[]; submission: string | null }
interface PreviousOperation { id: string; position: number; state: string; record: string }

// Keep old links and execution results. Splitting an outstanding group could change what the recipient consented to.
export async function migrateRequests(db: Queryable, vault: Vault) {
  await db.query('LOCK TABLE requests, operations IN ACCESS EXCLUSIVE MODE');
  await db.query("UPDATE requests SET state='expired',answered_at=now() WHERE state='pending' AND expires_at<=now()");
  await db.query('DECLARE previous_requests NO SCROLL CURSOR FOR SELECT id,record,state FROM requests');
  for (;;) {
    const { rows } = await db.query<{ id: string; record: string; state: string }>('FETCH 100 FROM previous_requests');
    if (!rows.length) break;
    for (const row of rows) {
      const { operations, creatorActor, submission } = await vault.decrypt<PreviousRequest>(row.record, 'request:' + row.id);
      if (!operations?.length) throw new Error('Missing requested operation in ' + row.id);
      let performed: PreviousOperation[] = [];
      if (operations.length > 1) {
        performed = (await db.query<PreviousOperation>('SELECT id,position,state,record FROM operations WHERE request_id=$1', [row.id])).rows;
        if (row.state === 'pending' || performed.some(op => ['stopped', 'in_progress'].includes(op.state)))
          throw new Error('Finish or close the outstanding multi-operation request before migrating: ' + row.id);
        if (performed.some(op => !Number.isInteger(op.position) || op.position < 0 || op.position >= operations.length))
          throw new Error('Invalid operation position in request ' + row.id);
      }
      for (const [position, operation] of operations.entries()) {
        const id = position === 0 ? row.id : randomUUID();
        const record = await vault.encrypt({ operation, creatorActor, submission: operations.length === 1 ? submission : null }, 'request:' + id);
        if (position === 0) {
          await db.query('UPDATE requests SET record=$2 WHERE id=$1', [id, record]);
          continue;
        }
        await db.query(`INSERT INTO requests(id,from_id,to_id,owner_id,message,record,proposal,code_hash,attempts,state,expires_at,created_at,answered_at,answered_by)
          SELECT $2,from_id,to_id,owner_id,message,$3,proposal,code_hash,attempts,state,expires_at,created_at,answered_at,answered_by FROM requests WHERE id=$1`,
        [row.id, id, record]);
        const made = performed.find(op => op.position === position);
        if (made) {
          const context = 'operation:' + made.id;
          const snapshot = await vault.decrypt<{ actor: Actor }>(made.record, context);
          if (snapshot.actor.approvalId === row.id) snapshot.actor.approvalId = id;
          await db.query('UPDATE operations SET request_id=$2,record=$3 WHERE id=$1', [made.id, id, await vault.encrypt(snapshot, context)]);
        }
      }
    }
  }
  await db.query('CLOSE previous_requests');
  await db.query('ALTER TABLE requests RENAME COLUMN record TO operation_record');
  await db.query('ALTER TABLE operations DROP COLUMN position, ADD UNIQUE(request_id)');
}
