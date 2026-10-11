import type { Database } from './database.js';
import type { Vault } from './vault.js';
import type { Actor } from './authorization.js';
import type { RequestedOperation, JsonValue } from '../shared/contracts.js';
import type { DefinitionCall, OperationWaiting } from '../shared/executions.js';

interface PreviousSnapshot {
  actor: Actor; operations: DefinitionCall[]; index: number; results: Array<JsonValue | null>;
  proofs: Array<string | null>; inFlight: number | null; continuation: OperationWaiting['continuation'];
}
interface PreviousRequest {
  id: string; from_id: string; to_id: string | null; message: string; operations: string;
  results: Array<JsonValue | null>; state: string; code_hash: string | null; attempts: number;
  expires_at: Date; created_at: Date; proposal: unknown; credential_id: string | null;
}
// Move persisted authority once. Runtime code only reads the execution schema.
export async function migrateExecutions(db: Database, vault: Vault) {
  await db.transaction(async connection => {
    await connection.query('SELECT pg_advisory_xact_lock(736023746)');
    if (await db.one("SELECT 1 FROM schema_migrations WHERE name='independent-operation-executions'", [], connection)) return;
    const previous = await db.one("SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='approval_requests' AND column_name='operations'", [], connection);
    const requests = previous ? await db.all<PreviousRequest>('SELECT * FROM approval_requests', [], connection) : [];
    for (const request of requests) {
      const requested = await vault.decrypt<RequestedOperation[]>(request.operations, 'request-operations:' + request.id);
      const row = await db.one<{ snapshot: string; state: string }>('SELECT snapshot,state FROM executions WHERE id=$1', [request.id], connection);
      const saved = row ? await vault.decrypt<PreviousSnapshot>(row.snapshot, 'operation-execution:' + request.id) : null;
      const index = request.state === 'approved' ? requested.length : Math.max(0, request.results.findIndex(result => result === null ||
        typeof result === 'object' && !Array.isArray(result) && ('error' in result || 'pending' in result)));
      const creatorActor: Actor = { id: request.from_id, ...(request.credential_id ? { credentialId: request.credential_id } : {}) };
      const snapshot = { ...(saved ?? { actor: creatorActor, operations: requested, index, results: request.results,
        proofs: requested.map(() => null), inFlight: null, continuation: null }), creatorActor,
        agreementIndex: request.proposal ? saved?.index ?? index : null,
        responders: request.to_id ? [request.to_id] : [],
        submissionDigest: null,
        operations: saved?.operations.map((operation, index) => ({ inputs: request.proposal
          ? index === saved.index ? requested[0]?.inputs ?? [] : [] : requested[index]?.inputs ?? [], ...operation })) ?? requested };
      const response = request.state === 'approved' || request.state === 'running' ? 'accepted' : request.state;
      const uncertain = row?.state === 'uncertain' || saved?.inFlight != null;
      const state = request.state === 'approved' ? 'succeeded' : ['declined', 'cancelled', 'expired'].includes(request.state)
        ? uncertain ? 'uncertain' : 'cancelled' : request.state === 'running' ? 'running' : 'waiting';
      await connection.query(`INSERT INTO executions(id,actor_id,creator_id,responder_id,message,proposal,code_hash,attempts,response,state,wait,snapshot,expires_at,created_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        ON CONFLICT(id) DO UPDATE SET creator_id=$3,responder_id=$4,message=$5,proposal=$6,code_hash=$7,attempts=$8,response=$9,snapshot=$12,
          state=CASE WHEN $10 IN ('cancelled','uncertain') THEN $10 ELSE executions.state END,
          wait=CASE WHEN $10 IN ('cancelled','uncertain') THEN NULL ELSE executions.wait END`,
      [request.id, snapshot.actor.id, request.from_id, request.to_id, request.message, request.proposal ? JSON.stringify(request.proposal) : null,
        request.code_hash, request.attempts, response, state, state === 'waiting' ? 'approval' : null,
        await vault.encrypt(snapshot, 'operation-execution:' + request.id), request.expires_at, request.created_at]);
    }
    const direct = await db.all<{ id: string; actor_id: string; snapshot: string }>('SELECT id,actor_id,snapshot FROM executions WHERE creator_id IS NULL', [], connection);
    for (const row of direct) {
      const saved = await vault.decrypt<PreviousSnapshot>(row.snapshot, 'operation-execution:' + row.id);
      await connection.query('UPDATE executions SET creator_id=$2,snapshot=$3 WHERE id=$1', [row.id, row.actor_id,
        await vault.encrypt({ ...saved, creatorActor: saved.actor, agreementIndex: null, responders: [], submissionDigest: null, operations: saved.operations.map(operation => ({ ...operation, inputs: [] })) }, 'operation-execution:' + row.id)]);
    }
    if (previous) await connection.query(`ALTER TABLE approval_requests
      DROP COLUMN from_id, DROP COLUMN to_id, DROP COLUMN message, DROP COLUMN operations, DROP COLUMN results,
      DROP COLUMN state, DROP COLUMN code_hash, DROP COLUMN attempts, DROP COLUMN expires_at, DROP COLUMN created_at,
      DROP COLUMN finished_at, DROP COLUMN proposal, DROP COLUMN credential_id,
      DROP COLUMN IF EXISTS private_input, DROP COLUMN IF EXISTS continue_url,
      ADD CONSTRAINT approval_requests_execution FOREIGN KEY(id) REFERENCES executions(id) ON DELETE CASCADE`);
    await connection.query('ALTER TABLE executions ALTER COLUMN creator_id SET NOT NULL');
    await connection.query("INSERT INTO schema_migrations(name) VALUES('independent-operation-executions')");
  });
}
