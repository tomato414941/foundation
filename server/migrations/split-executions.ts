import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { Database } from '../database.js';
import type { Vault } from '../vault.js';
import type { Actor } from '../authorization.js';
import type { JsonValue, RequestedOperation } from '../../shared/contracts.js';

type Answer = 'pending' | 'accepted' | 'declined' | 'cancelled' | 'expired';
interface Execution {
  id: string; actor_id: string; creator_id: string; owner_id: string | null; responder_id: string | null; message: string;
  proposal: unknown; code_hash: string | null; attempts: number; response: 'none' | Answer;
  state: 'waiting' | 'running' | 'succeeded' | 'failed' | 'uncertain' | 'cancelled'; snapshot: string;
  expires_at: Date; created_at: Date;
}
interface Delivery { id: string; execution_id: string; from_id: string; to_id: string | null; message: string; state: Answer; answered_at: Date | null }
interface Snapshot {
  actor: Actor; creatorActor?: Actor; operations: RequestedOperation[]; index: number; results: Array<JsonValue | null>;
  proofs?: Array<string | null>; submissionDigest?: string | null; agreementIndex?: number | null;
}
const answers = { pending: 'pending', accepted: 'approved', declined: 'declined', cancelled: 'withdrawn', expired: 'expired' } as const;
const outcome = (value: JsonValue | null | undefined) =>
  value && typeof value === 'object' && !Array.isArray(value) && typeof value.state === 'string' ? value.state : null;
// A result keeps its failure under the name operations give it.
function renamed(value: JsonValue | null | undefined): JsonValue | null {
  if (outcome(value) === 'uncertain')
    return { error: { code: 'operation_uncertain', message: 'Check the result before making this operation again.' } };
  if (!value || typeof value !== 'object' || Array.isArray(value) || !value.error || typeof value.error !== 'object' ||
    Array.isArray(value.error) || typeof value.error.code !== 'string') return value ?? null;
  return { ...value, error: { ...value.error, code: value.error.code.replace(/^execution_/, 'operation_') } };
}

// An execution kept both what waited for someone and what was done. Each becomes a request when someone was asked, as
// that request stood, and an operation for each step that was made, which names the request it came from. In an
// approved request, the steps not made yet stay to be made by their owner, or stay stopped where the execution was
// cancelled. One that asked no one and made nothing leaves nothing behind.
export async function splitExecutions(db: Database, vault: Vault) {
  await db.transaction(async connection => {
    await connection.query('SELECT pg_advisory_xact_lock(736023752)');
    if (await db.one("SELECT 1 FROM schema_migrations WHERE name='015-requests-and-operations'", [], connection)) return;
    await connection.query(await readFile(new URL('./015-requests-and-operations.sql', import.meta.url), 'utf8'));
    const executions = await db.all<Execution>('SELECT * FROM executions ORDER BY created_at,id', [], connection);
    const deliveries = await db.all<Delivery>(
      'SELECT id,execution_id,from_id,to_id,message,state,answered_at FROM execution_requests ORDER BY created_at,id', [], connection);
    for (const row of executions) {
      const snapshot = await vault.decrypt<Snapshot>(row.snapshot, 'operation-execution:' + row.id);
      const last = deliveries.filter(delivery => delivery.execution_id === row.id).at(-1);
      const done = row.state === 'succeeded' ? snapshot.operations.length : snapshot.index;
      const fault = row.state === 'failed' ? 'failed' as const : row.state === 'uncertain' ||
        row.state === 'cancelled' && outcome(snapshot.results[snapshot.index]) === 'uncertain' ? 'uncertain' as const : null;
      if (!last && !done && !fault) continue;
      let requestId: string | null = null, approved = false;
      if (last) {
        requestId = last.id;
        const state = answers[last.state];
        approved = state === 'approved';
        const answeredBy = state === 'approved' || state === 'declined' ? row.responder_id ?? last.to_id : null;
        const record = { creatorActor: snapshot.creatorActor ?? snapshot.actor, operations: snapshot.operations,
          submission: snapshot.submissionDigest ?? null };
        await connection.query(`INSERT INTO requests(id,from_id,to_id,owner_id,message,record,proposal,code_hash,attempts,state,
          expires_at,created_at,answered_at,answered_by) VALUES($1,$2,$3,(SELECT id FROM principals WHERE id=$4),$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        [requestId, last.from_id, row.responder_id ?? last.to_id, row.owner_id, last.message || row.message,
          await vault.encrypt(record, 'request:' + requestId), row.proposal ? JSON.stringify(row.proposal) : null,
          state === 'pending' ? row.code_hash : null, row.attempts, state, row.expires_at, row.created_at,
          state === 'pending' ? null : last.answered_at ?? row.created_at, answeredBy]);
      }
      for (const [position, operation] of snapshot.operations.entries()) {
        const state = position < done ? 'succeeded' : position === done && fault ? fault
          : approved ? row.state === 'cancelled' ? 'cancelled' : 'stopped' : null;
        if (!state) continue;
        // The actor makes it under the request it was approved in, with the agreement given to that step alone.
        const actor: Actor = { ...snapshot.actor };
        delete actor.requestId;
        if (actor.agreedBy && snapshot.agreementIndex !== position) { delete actor.agreedBy; delete actor.approvalId; }
        if (actor.approvalId && requestId) { actor.approvalId = requestId; actor.approvalIndex = position; }
        else { delete actor.approvalId; delete actor.approvalIndex; }
        const id = snapshot.operations.length === 1 ? row.id : randomUUID();
        const record = { actor, input: operation.input, result: state === 'succeeded' || state === fault ? renamed(snapshot.results[position]) : null,
          proof: snapshot.proofs?.[position] ?? null, continuation: null, inFlight: false, submission: null };
        await connection.query(`INSERT INTO operations(id,request_id,position,owner_id,actor_id,name,state,record,created_at,updated_at)
          VALUES($1,$2,$3,(SELECT id FROM principals WHERE id=$4),$5,$6,$7,$8,$9,$9)`,
        [id, requestId, requestId ? position : null, row.owner_id, row.actor_id, operation.name, state,
          await vault.encrypt(record, 'operation:' + id), row.created_at]);
      }
    }
    await connection.query('DROP TABLE execution_requests');
    await connection.query('DROP TABLE executions');
    await connection.query("INSERT INTO schema_migrations(name) VALUES('015-requests-and-operations')");
  });
}
