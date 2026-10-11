import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { flowFixture } from './flow-support.js';
import { migrateOperationExecutions } from '../server/migrate-operation-executions.js';
import { OperationExecution } from '../shared/operations.js';
import { decode } from '../shared/encryption.js';

test('保存済みの入力待ちを移行し、同じ実行IDと暗号化済みの項目を使って続行する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const id = randomUUID(), interruptedId = randomUUID(), publicInput = { ownerId: f.owner.actor.id, name: 'Migrated value', value: '', environmentIds: [] };
  const requested = [{ name: 'variable.save', input: publicInput, inputs: [{ pointer: '/value', label: 'Token', secret: true, multiline: false }] }];
  const snapshot = { actor: { id: f.owner.actor.id, approvalId: id }, operations: [{ name: 'variable.save', input: publicInput }],
    index: 0, results: [{ pending: true }], proofs: [null], inFlight: null, continuation: null };
  await f.context.db.transaction(async connection => {
    await connection.query('DROP TABLE approval_requests CASCADE');
    await connection.query(`CREATE TABLE approval_requests(id uuid PRIMARY KEY,from_id uuid,to_id uuid,message text,operations text,
      results jsonb,state text,code_hash text,attempts integer,expires_at timestamptz,created_at timestamptz,
      finished_at timestamptz,proposal jsonb,credential_id uuid)`);
    await connection.query('ALTER TABLE operation_executions ALTER COLUMN creator_id DROP NOT NULL');
    await connection.query(`INSERT INTO operation_executions(id,actor_id,state,wait,snapshot,expires_at)
      VALUES($1,$2,'waiting','input',$3,now()+interval '1 day')`, [id, f.owner.actor.id,
      await f.context.vault.encrypt(snapshot, 'operation-execution:' + id)]);
    await connection.query(`INSERT INTO approval_requests(id,from_id,to_id,message,operations,results,state,attempts,expires_at,created_at)
      VALUES($1,$2,$3,'Resume this value',$4,'[{"pending":true}]','running',0,now()+interval '1 day',now())`,
    [id, f.stranger.actor.id, f.owner.actor.id, await f.context.vault.encrypt(requested, 'request-operations:' + id)]);
    await connection.query(`INSERT INTO operation_executions(id,actor_id,state,snapshot,expires_at)
      VALUES($1,$2,'uncertain',$3,now()-interval '1 second')`, [interruptedId, f.owner.actor.id,
      await f.context.vault.encrypt({ ...snapshot, actor: { id: f.owner.actor.id, approvalId: interruptedId }, inFlight: 0 }, 'operation-execution:' + interruptedId)]);
    await connection.query(`INSERT INTO approval_requests(id,from_id,to_id,message,operations,results,state,attempts,expires_at,created_at)
      VALUES($1,$2,$3,'Check this interrupted operation',$4,'[{"pending":true}]','expired',0,now()-interval '1 second',now())`,
      [interruptedId, f.stranger.actor.id, f.owner.actor.id, await f.context.vault.encrypt(requested, 'request-operations:' + interruptedId)]);
    await connection.query("DELETE FROM schema_migrations WHERE name='independent-operation-executions'");
  });
  await migrateOperationExecutions(f.context.db, f.context.vault);
  await migrateOperationExecutions(f.context.db, f.context.vault);
  const interrupted = await f.client.api.json('/api/operation-executions/' + interruptedId, {}, OperationExecution);
  assert.equal(interrupted.state, 'uncertain'); assert.equal(interrupted.response, 'expired');
  const migrated = await f.client.api.json('/api/operation-executions/' + id, {}, OperationExecution);
  assert.equal(migrated.creator.id, f.stranger.actor.id); assert.equal(migrated.responder?.id, f.owner.actor.id);
  assert.equal(migrated.response, 'accepted'); assert.equal(migrated.waiting?.index, 0);
  assert.equal(migrated.operations[0]?.inputs[0]?.label, 'Token');
  const saved = await f.operations.continue(id, { value: 'migrated-secret' });
  if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected the resumed value.');
  assert.equal(decode(await f.client.reveal(saved.resource.id)), 'migrated-secret');
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'confidential-value');
  const completed = await f.api(f.stranger.token).json('/api/operation-executions/' + id, {}, OperationExecution);
  assert.equal(completed.state, 'succeeded'); assert.equal((completed.results[0] as { id: string }).id, saved.resource.id);
});
