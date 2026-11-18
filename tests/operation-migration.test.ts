import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { flowFixture } from './flow-support.js';
import { removeEnvironments } from '../server/migrations/remove-environments.js';
import { splitExecutions } from '../server/migrations/split-executions.js';
import { listOf } from '../shared/contracts.js';
import { OperationView, RequestView } from '../shared/operations.js';
import { decode } from '../shared/encryption.js';

type Fixture = Awaited<ReturnType<typeof flowFixture>>;
// The tables a database kept before requests and operations: executions, and the requests that delivered them.
const earlierTables = `
CREATE TABLE executions (
  id uuid PRIMARY KEY,
  actor_id uuid NOT NULL,
  creator_id uuid NOT NULL,
  owner_id uuid REFERENCES principals(id) ON DELETE CASCADE,
  responder_id uuid,
  message text NOT NULL DEFAULT '',
  proposal jsonb,
  code_hash text,
  attempts integer NOT NULL DEFAULT 0,
  response text NOT NULL DEFAULT 'none' CHECK(response IN ('none','pending','accepted','declined','cancelled','expired')),
  state text NOT NULL CHECK(state IN ('waiting','running','succeeded','failed','uncertain','cancelled')),
  wait text CHECK(wait IN ('approval','input','execution')),
  snapshot text NOT NULL,
  revision integer NOT NULL DEFAULT 1,
  lease_token uuid,
  lease_until timestamptz,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX executions_actor ON executions(actor_id,created_at DESC);
CREATE INDEX executions_recipient ON executions(responder_id,state,created_at);
CREATE TABLE requests (
  id uuid PRIMARY KEY,
  execution_id uuid NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  from_id uuid NOT NULL,
  to_id uuid,
  message text NOT NULL DEFAULT '',
  purpose text NOT NULL CHECK(purpose IN ('input','approval')),
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','accepted','declined','cancelled','expired')),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  answered_at timestamptz
);
CREATE UNIQUE INDEX request_pending ON requests(execution_id) WHERE state='pending';
CREATE INDEX request_recipient ON requests(to_id,state,created_at);
CREATE TABLE request_links (
  token_hash text PRIMARY KEY,
  request_id uuid NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL
);
CREATE TABLE oauth_relays (
  id uuid PRIMARY KEY,
  execution_id uuid NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  operation_index integer NOT NULL,
  actor_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  binding_id uuid NOT NULL,
  state_digest text NOT NULL UNIQUE,
  callback_digest text,
  sealed jsonb,
  expires_at timestamptz NOT NULL,
  received_at timestamptz
);`;
// What a database held before the migrations that remove execution environments and split executions: their tables
// and columns, and the executions they recorded.
async function earlierDatabase(f: Fixture) {
  await f.db.pool.query('DROP TABLE oauth_relays; DROP TABLE request_links; DROP TABLE operations; DROP TABLE requests;' + earlierTables);
  for (const table of ['function_invocations', 'function_settings', 'environment_processes', 'execution_tasks',
    'executor_environments', 'environment_deletions', 'environment_jobs']) await f.db.pool.query(`CREATE TABLE ${table}(id uuid)`);
  await f.db.pool.query("ALTER TABLE billing_events ADD COLUMN meter text NOT NULL DEFAULT 'storage'");
  await f.db.pool.query('ALTER TABLE usage_limits ADD COLUMN compute_seconds bigint');
  await f.db.pool.query('ALTER TABLE credentials ADD COLUMN environment_id uuid');
  await f.db.pool.query("DELETE FROM schema_migrations WHERE name IN ('012-remove-environments','015-requests-and-operations')");
}
interface Recorded {
  id?: string; creator: string; actor: { id: string; approvalId?: string }; responder?: string; owner?: string;
  response: string; state: string; wait?: string; index: number; results: unknown[];
  operations: Array<{ name: string; input: Record<string, unknown> }>;
  delivery?: { id: string; state: string; message?: string };
}
async function record(f: Fixture, execution: Recorded) {
  const id = execution.id ?? randomUUID();
  const snapshot = { actor: execution.actor, creatorActor: { id: execution.creator }, index: execution.index, results: execution.results,
    operations: execution.operations.map(operation => ({ ...operation, inputs: [] })), proofs: execution.operations.map(() => null),
    inFlight: null, continuation: null, submissionDigest: null };
  await f.db.pool.query(`INSERT INTO executions(id,actor_id,creator_id,owner_id,responder_id,response,state,wait,snapshot,expires_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now()+interval '1 day')`, [id, execution.actor.id, execution.creator,
    execution.owner ?? null, execution.responder ?? null, execution.response, execution.state, execution.wait ?? null,
    await f.context.vault.encrypt(snapshot, 'operation-execution:' + id)]);
  if (execution.delivery) await f.db.pool.query(`INSERT INTO requests(id,execution_id,from_id,to_id,message,purpose,state,expires_at,answered_at)
    VALUES($1,$2,$3,$4,$5,'input',$6,now()+interval '1 day',CASE WHEN $6='pending' THEN NULL ELSE now() END)`,
  [execution.delivery.id, id, execution.creator, execution.responder ?? null, execution.delivery.message ?? '', execution.delivery.state]);
  return id;
}

test('実行の記録を依頼と操作に分け、行われた操作と依頼を移し、何も行われずに終わった記録は捨てる', async t => {
  const f = await flowFixture(); t.after(f.close);
  const owner = f.owner.actor.id, stranger = f.stranger.actor.id;
  await earlierDatabase(f);
  const group = { name: 'principal.create', input: { ownerId: owner, name: 'Recorded group' } };
  const direct = await record(f, { creator: owner, actor: { id: owner }, owner, response: 'none', state: 'succeeded', index: 1,
    results: [{ id: randomUUID(), name: 'Recorded group' }], operations: [group] });
  const approvedId = randomUUID(), approved = randomUUID();
  await record(f, { id: approvedId, creator: stranger, actor: { id: owner, approvalId: approvedId }, responder: owner, owner,
    response: 'accepted', state: 'failed', index: 1,
    results: [{ id: randomUUID(), name: 'Approved group' }, { error: { code: 'execution_failed', message: 'The execution did not complete successfully.' } }],
    operations: [{ name: 'principal.create', input: { ownerId: owner, name: 'Approved group' } },
      { name: 'principal.rename', input: { id: owner, name: 'Renamed after migration' } },
      { name: 'principal.create', input: { ownerId: owner, name: 'Made after the retry' } }],
    delivery: { id: approved, state: 'accepted', message: 'Set up the owner' } });
  const withdrawn = randomUUID();
  await record(f, { creator: stranger, actor: { id: stranger }, responder: owner, owner, response: 'cancelled', state: 'cancelled', index: 0,
    results: [null], operations: [group], delivery: { id: withdrawn, state: 'cancelled' } });
  const forgotten = await record(f, { creator: owner, actor: { id: owner }, owner, response: 'expired', state: 'cancelled', wait: 'input',
    index: 0, results: [null], operations: [{ name: 'variable.save', input: { ownerId: owner, name: 'Never entered' } }] });
  const environment = await record(f, { creator: owner, actor: { id: owner }, owner, response: 'none', state: 'succeeded', index: 1,
    results: [{ ok: true }], operations: [{ name: 'run.execute', input: { ownerId: owner, environmentId: randomUUID() } }] });
  const pending = randomUUID();
  await record(f, { creator: stranger, actor: { id: stranger }, responder: owner, owner, response: 'pending', state: 'waiting', wait: 'approval',
    index: 0, results: [null], operations: [{ name: 'variable.save', input: { ownerId: owner, name: 'Value without environments',
      environmentIds: [randomUUID()] } }], delivery: { id: pending, state: 'pending' } });

  await removeEnvironments(f.context.db, f.context.vault);
  await splitExecutions(f.context.db, f.context.vault);
  await splitExecutions(f.context.db, f.context.vault);
  await f.context.db.assertReady();
  for (const table of ['executions', 'execution_requests'])
    assert.equal((await f.db.one<{ found: string | null }>('SELECT to_regclass($1) AS found', [table]))?.found, null);

  const made = await f.client.api.json('/api/operations/' + direct, {}, OperationView);
  assert.equal(made.state, 'succeeded'); assert.equal(made.request, null); assert.equal((made.result as { name: string }).name, 'Recorded group');
  for (const id of [forgotten, environment]) assert.equal(await f.db.one('SELECT 1 FROM operations WHERE id=$1', [id]), undefined);
  const ended = await f.client.api.json('/api/requests/' + withdrawn, {}, RequestView);
  assert.equal(ended.state, 'withdrawn'); assert.deepEqual(ended.performed, []);

  const answered = await f.api(f.stranger.token).json('/api/requests/' + approved, {}, RequestView);
  assert.equal(answered.state, 'approved'); assert.equal(answered.message, 'Set up the owner');
  assert.deepEqual(answered.performed.map(entry => entry.state), ['succeeded', 'failed', 'stopped']);
  const failed = await f.client.api.json('/api/operations/' + answered.performed[1]!.id, {}, OperationView);
  assert.equal(failed.error?.code, 'operation_failed'); assert.equal(failed.canPerform, true);
  await f.client.api.json('/api/operations/' + failed.id + '/perform', { method: 'POST', body: {} }, OperationView);
  const continued = await f.client.api.json('/api/requests/' + approved, {}, RequestView);
  assert.deepEqual(continued.performed.map(entry => entry.state), ['succeeded', 'succeeded', 'succeeded']);
  assert.equal((await f.principals.get(owner)).name, 'Renamed after migration');

  const waiting = await f.client.api.json('/api/requests/' + pending, {}, RequestView);
  assert.equal(waiting.state, 'pending');
  assert.deepEqual(waiting.operations[0]?.input, { ownerId: owner, name: 'Value without environments' });
  const accepted = await f.client.api.json('/api/requests/' + pending + '/approve', { method: 'POST', body: {} }, RequestView);
  const saved = await f.operations.continue(accepted.performed[0]!.id, { value: 'kept-secret' });
  if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected the saved value.');
  assert.equal(decode(await f.client.reveal(saved.resource.id)), 'kept-secret');
  const history = await f.client.api.json('/api/principals/' + owner + '/operations', {}, listOf(OperationView));
  assert.ok(history.items.some(item => item.id === direct));
});
