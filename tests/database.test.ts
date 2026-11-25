import test from 'node:test';
import { randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import { enroll, fixture } from './support.js';
import { createContext } from '../server/context.js';
import { Accounts } from '../server/accounts.js';
import { hash } from '../shared/digest.js';

test('空のDBでは起動せず、移行コマンドで準備したDBで起動し、移行し直してもアカウントを保つ', async t => {
  const f = await fixture(); t.after(f.close);
  const schema = (await f.db.one<{ schema: string }>('SELECT current_schema() AS schema'))!.schema;
  await f.db.pool.query(`DROP SCHEMA "${schema}" CASCADE`);
  await f.db.pool.query(`CREATE SCHEMA "${schema}"`);
  await assert.rejects(createContext(f.config, { db: f.db, mailer: f.mailer }), /npm run migrate/);
  const prepared = await createContext(f.config, { db: f.db, mailer: f.mailer }, { migrate: true });
  const person = await enroll(prepared.authentication, 'Retained account');
  await createContext(f.config, { db: f.db, mailer: f.mailer }, { migrate: true });
  const restarted = await createContext(f.config, { db: f.db, mailer: f.mailer });
  const actor = (await restarted.authentication.authenticate(person.token))!;
  assert.equal((await restarted.principals.get(actor.id)).name, 'Retained account');
});

test('Foundationの移行で準備していない使用中のDBは移行を断る', async t => {
  const f = await fixture(); t.after(f.close);
  await f.db.pool.query('DROP TABLE schema_migrations');
  await assert.rejects(f.db.migrate(f.config), /not prepared by Foundation migrations/);
});

test('移行で過去の依頼と実行結果を保ち、確認待ちの単独依頼は元のリンクで承認する', async t => {
  const f = await fixture(); t.after(f.close);
  const sender = await f.person('Sender'), receiver = await f.person('Receiver');
  const to = receiver.actor.id;
  const operation = (name: string) => ({ name: 'principal.create', input: { ownerId: '$approver', name }, inputs: [] });
  const single = operation('Pending project');
  const fingerprint = await hash({ operations: [single], to, message: '', expiresInMinutes: 30, invitation: false });
  await f.db.pool.query(`DELETE FROM schema_migrations WHERE name='018-single-request-operation';
    ALTER TABLE requests RENAME COLUMN operation_record TO record;
    ALTER TABLE operations DROP CONSTRAINT operations_request_id_key, ADD COLUMN position integer;
    ALTER TABLE operations ADD UNIQUE(request_id,position)`);
  const legacy = async (operations: ReturnType<typeof operation>[], state: string, submission: string | null = null) => {
    const id = randomUUID();
    const record = await f.vault.encrypt({ creatorActor: sender.actor, operations, submission }, 'request:' + id);
    await f.db.pool.query(`INSERT INTO requests(id,from_id,to_id,owner_id,state,record,expires_at,answered_at,answered_by)
      VALUES($1,$2,$3,$3,$4,$5,now()+interval '1 day',CASE WHEN $4='approved' THEN now() END,
        CASE WHEN $4='approved' THEN $3::uuid END)`, [id, sender.actor.id, to, state, record]);
    return id;
  };
  const pending = await legacy([single], 'pending', fingerprint);
  const archived = await legacy([operation('First project'), operation('Second project')], 'approved');
  const unfinished = await legacy([operation('Other project'), operation('Last project')], 'pending');
  const made = [];
  for (const [position, name] of ['First project', 'Second project'].entries()) {
    const id = randomUUID(), result = { id: randomUUID(), name };
    const snapshot = { actor: { id: to, approvalId: archived, approvalIndex: position }, input: { ownerId: to, name },
      result, proof: null, continuation: null, inFlight: false, submission: null };
    await f.db.pool.query(`INSERT INTO operations(id,request_id,position,owner_id,actor_id,name,state,record)
      VALUES($1,$2,$3,$4,$4,'principal.create','succeeded',$5)`,
    [id, archived, position, to, await f.vault.encrypt(snapshot, 'operation:' + id)]);
    made.push({ id, result });
  }
  await assert.rejects(f.db.migrate(f.config), /outstanding multi-operation request/);
  await f.db.pool.query("UPDATE requests SET expires_at=now()-interval '1 second' WHERE id=$1", [unfinished]);
  await f.db.migrate(f.config);
  await f.db.migrate(f.config);
  const c = await createContext(f.config, { db: f.db });
  const history = (await c.requests.list(sender.actor)).items;
  assert.equal(history.length, 5);
  const expired = history.filter(row => row.state === 'expired');
  assert.deepEqual(expired.map(row => row.operation.input.name).sort(), ['Last project', 'Other project']);
  assert.ok(expired.every(row => row.performed === null));
  assert.equal((await c.requests.get(sender.actor, archived)).operation.input.name, 'First project');
  for (const item of made) {
    const past = await c.operations.get(receiver.actor, item.id);
    const approval = await c.requests.get(sender.actor, past.requestId!);
    assert.equal(approval.state, 'approved');
    assert.equal(approval.operation.input.name, item.result.name);
    assert.deepEqual(approval.performed, { id: item.id, state: 'succeeded' });
    assert.deepEqual(past.result, item.result);
  }
  const replay = await c.requests.create(sender.actor, { id: pending, to, operation: single });
  assert.equal(replay.id, pending); assert.equal(replay.state, 'pending');
  const approved = await c.requests.approve(receiver.actor, pending);
  assert.equal(approved.performed?.state, 'succeeded');
  const entries = [];
  for await (const line of new Accounts(c).export(receiver.actor, to)) entries.push(JSON.parse(line));
  const exported = entries.find(entry => entry.request?.id === pending).request;
  assert.equal(exported.operation.input.name, 'Pending project');
  assert.equal(entries.find(entry => entry.operation?.id === exported.performed.id).operation.requestId, pending);
});
