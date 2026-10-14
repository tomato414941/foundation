import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { SchemaMigration } from '../server/database.js';
import { Accounts } from '../server/accounts.js';

test('移行コマンドで既存のアカウントを保持してDBを準備し、準備済みのDBで起動する', async t => {
  const f = await fixture(); t.after(f.close);
  const person = await f.person('Retained account');
  await f.db.pool.query('DELETE FROM schema_migrations WHERE name=$1', [SchemaMigration]);
  await assert.rejects(createContext(f.config, { db: f.db, mailer: f.mailer }), /npm run migrate/);
  await createContext(f.config, { db: f.db, mailer: f.mailer }, { migrate: true });
  const restarted = await createContext(f.config, { db: f.db, mailer: f.mailer });
  assert.equal((await restarted.authentication.authenticate(person.token))!.id, person.actor.id);
  assert.equal((await restarted.principals.get(person.actor.id)).name, 'Retained account');
});

test('保存済みのHTTP実行の結果と実行者を保持して履歴へ移し、一覧とエクスポートで読む', async t => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person('Historical owner'), performer = await f.person('Historical performer');
  await createContext(f.config, { db: f.db, mailer: f.mailer });
  await f.db.pool.query(`CREATE TABLE runs (
    id uuid PRIMARY KEY,owner_id uuid NOT NULL REFERENCES principals(id),actor_id uuid NOT NULL REFERENCES principals(id),
    resource_id uuid,kind text NOT NULL,state text NOT NULL,private_input text NOT NULL,result jsonb,error text,
    lease_until timestamptz,lease_token uuid,created_at timestamptz NOT NULL,started_at timestamptz,finished_at timestamptz
  )`);
  const succeeded = randomUUID(), failed = randomUUID(), created = new Date('2026-10-07T11:47:15Z');
  const response = { status: 200, headers: { 'content-type': 'application/json' }, body: '{"retained":true}' };
  for (const [id, state, result, error] of [[succeeded, 'succeeded', response, null], [failed, 'failed', null, 'Destination rejected']] as const)
    await f.db.pool.query(`INSERT INTO runs(id,owner_id,actor_id,kind,state,private_input,result,error,created_at,started_at,finished_at)
      VALUES($1,$2,$3,'http',$4,'',$5,$6,$7,$7,$7)`, [id, owner.actor.id, performer.actor.id, state, result, error, created]);
  await f.db.pool.query('DELETE FROM schema_migrations WHERE name=ANY($1::text[])', [[SchemaMigration, 'historical-server-runs']]);
  const c = await createContext(f.config, { db: f.db, mailer: f.mailer }, { migrate: true });
  await createContext(f.config, { db: f.db, mailer: f.mailer }, { migrate: true });
  await f.db.pool.query('UPDATE executions SET expires_at=created_at WHERE id=ANY($1::uuid[])', [[succeeded, failed]]);
  const history = await c.executions.list(owner.actor);
  assert.equal(history.items.length, 2);
  const completed = await c.executions.get(owner.actor, succeeded);
  assert.equal(completed.creator.id, performer.actor.id);
  assert.equal(completed.ownerId, owner.actor.id);
  assert.equal(completed.createdAt, created.toISOString());
  assert.equal(completed.state, 'succeeded');
  assert.deepEqual(completed.results[0], response);
  const rejected = await c.executions.get(performer.actor, failed);
  assert.equal(rejected.state, 'failed');
  assert.equal(rejected.error?.message, 'Destination rejected');
  assert.equal(rejected.canContinue, false);
  assert.equal(rejected.canCancel, false);
  await assert.rejects(c.executions.retry(performer.actor, failed), { status: 409, code: 'execution_changed' });
  const entries = [];
  for await (const line of new Accounts(c).export(owner.actor, owner.actor.id)) entries.push(JSON.parse(line));
  const exported = entries.filter(entry => entry.type === 'execution').map(entry => entry.execution);
  assert.equal(exported.length, 2);
  assert.deepEqual(exported.find(execution => execution.id === succeeded).results[0], response);
});
