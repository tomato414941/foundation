import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { flowFixture } from './flow-support.js';
import { migrateExecutions } from '../server/migrations/migrate-executions.js';
import { migrateRequests } from '../server/migrations/migrate-requests.js';
import { migrateHistory } from '../server/migrations/migrate-history.js';
import { ApprovalRequest } from '../shared/contracts.js';
import { Execution } from '../shared/executions.js';
import { decode } from '../shared/encryption.js';

test('保存済みの入力待ちを移行し、同じ実行IDと暗号化済みの項目を使って続行する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const id = randomUUID(), interruptedId = randomUUID(), publicInput = { ownerId: f.owner.actor.id, name: 'Migrated value', value: '', environmentIds: [] };
  const requested = [{ name: 'variable.save', input: publicInput, inputs: [{ pointer: '/value', label: 'Token', secret: true, multiline: false }] }];
  const snapshot = { actor: { id: f.owner.actor.id, approvalId: id }, operations: [{ name: 'variable.save', input: publicInput }],
    index: 0, results: [{ pending: true }], proofs: [null], inFlight: null, continuation: null };
  await f.context.db.transaction(async connection => {
    await connection.query('DROP TABLE IF EXISTS approval_requests CASCADE');
    await connection.query(`CREATE TABLE approval_requests(id uuid PRIMARY KEY,from_id uuid,to_id uuid,message text,operations text,
      results jsonb,state text,code_hash text,attempts integer,expires_at timestamptz,created_at timestamptz,
      finished_at timestamptz,proposal jsonb,credential_id uuid)`);
    await connection.query('ALTER TABLE executions ALTER COLUMN creator_id DROP NOT NULL');
    await connection.query(`INSERT INTO executions(id,actor_id,state,wait,snapshot,expires_at)
      VALUES($1,$2,'waiting','input',$3,now()+interval '1 day')`, [id, f.owner.actor.id,
      await f.context.vault.encrypt(snapshot, 'operation-execution:' + id)]);
    await connection.query(`INSERT INTO approval_requests(id,from_id,to_id,message,operations,results,state,attempts,expires_at,created_at)
      VALUES($1,$2,$3,'Resume this value',$4,'[{"pending":true}]','running',0,now()+interval '1 day',now())`,
    [id, f.stranger.actor.id, f.owner.actor.id, await f.context.vault.encrypt(requested, 'request-operations:' + id)]);
    await connection.query(`INSERT INTO executions(id,actor_id,state,snapshot,expires_at)
      VALUES($1,$2,'uncertain',$3,now()-interval '1 second')`, [interruptedId, f.owner.actor.id,
      await f.context.vault.encrypt({ ...snapshot, actor: { id: f.owner.actor.id, approvalId: interruptedId }, inFlight: 0 }, 'operation-execution:' + interruptedId)]);
    await connection.query(`INSERT INTO approval_requests(id,from_id,to_id,message,operations,results,state,attempts,expires_at,created_at)
      VALUES($1,$2,$3,'Check this interrupted operation',$4,'[{"pending":true}]','expired',0,now()-interval '1 second',now())`,
      [interruptedId, f.stranger.actor.id, f.owner.actor.id, await f.context.vault.encrypt(requested, 'request-operations:' + interruptedId)]);
    await connection.query("DELETE FROM schema_migrations WHERE name IN ('independent-operation-executions','independent-request-delivery')");
  });
  await migrateExecutions(f.context.db, f.context.vault);
  await migrateExecutions(f.context.db, f.context.vault);
  await migrateRequests(f.context.db);
  await migrateRequests(f.context.db);
  const interrupted = await f.client.api.json('/api/executions/' + interruptedId, {}, Execution);
  assert.equal(interrupted.state, 'uncertain');
  assert.equal((await f.client.api.json('/api/requests/' + interruptedId, {}, ApprovalRequest)).state, 'expired');
  const migrated = await f.client.api.json('/api/executions/' + id, {}, Execution);
  assert.equal(migrated.creator.id, f.stranger.actor.id);
  const delivered = await f.client.api.json('/api/requests/' + id, {}, ApprovalRequest);
  assert.equal(delivered.to?.id, f.owner.actor.id);
  assert.equal(delivered.state, 'accepted'); assert.equal(migrated.waiting?.index, 0);
  assert.equal(migrated.operations[0]?.inputs[0]?.label, 'Token');
  const saved = await f.operations.continue(id, { value: 'migrated-secret' });
  if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected the resumed value.');
  assert.equal(decode(await f.client.reveal(saved.resource.id)), 'migrated-secret');
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'confidential-value');
  const completed = await f.api(f.stranger.token).json('/api/executions/' + id, {}, Execution);
  assert.equal(completed.state, 'succeeded'); assert.equal((completed.results[0] as { id: string }).id, saved.resource.id);
});

test('実行の保存形式を更新しても依頼のURLと入力待ちの実行を保持し、承諾後に保存を完了する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const asked = await f.api(f.stranger.token).json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'variable.save', input: { ownerId: f.owner.actor.id, name: 'Retained input' } }] } }, ApprovalRequest);
  await f.db.pool.query('ALTER TABLE executions RENAME TO operation_executions');
  await f.db.pool.query("DELETE FROM schema_migrations WHERE name='001-foundation-schema'");
  await f.db.migrate();
  const retained = await f.client.api.json('/api/requests/' + asked.id, {}, ApprovalRequest);
  assert.equal(retained.url, asked.url);
  assert.equal(retained.executionId, asked.executionId);
  await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, ApprovalRequest);
  const saved = await f.operations.continue(asked.executionId, { value: 'retained-value' });
  if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected the retained execution to save.');
  assert.equal(decode(await f.client.reveal(saved.resource.id)), 'retained-value');
});

test('既存の実行先の処理を一件の実行として引き継ぎ、再開時に外部操作を一度だけ行う', async t => {
  const f = await flowFixture(); t.after(f.close);
  const task = await f.delegation.submit(f.owner.actor, f.request);
  await f.db.pool.query("DELETE FROM schema_migrations WHERE name='unified-execution-history'");
  await migrateHistory(f.context);
  const execution = await f.client.api.json('/api/executions/' + task.id, {}, Execution);
  assert.equal(execution.state, 'running');
  await f.executor.tick();
  const completed = await f.client.api.json('/api/executions/' + task.id, {}, Execution);
  assert.equal(completed.state, 'succeeded');
  assert.equal((await f.client.api.json('/api/executions/' + task.id, {}, Execution)).state, 'succeeded');
  assert.equal(f.requests.length, 1);
});
