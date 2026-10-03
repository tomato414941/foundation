import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Environments } from '../src/environments.mjs';
import { Payments, Stripe } from '../src/payments.mjs';
import { fixture, fakeStripe, modules, KEY, USER_A } from './helpers.mjs';

const deferred = () => Promise.withResolvers();
const result = (stdout = '') => ({ exitCode: 0, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0) });
class Runner {
  constructor(machines = new Set()) { this.name = 'fake'; this.machines = machines; this.stops = []; }
  async start({ id, onCreated }) { this.machines.add(id); onCreated?.(id); return { machine: id }; }
  async put() {}
  async remove() {}
  async exec() { return result(); }
  async stop(machine) { this.stops.push(machine); await this.stopping?.(machine); this.machines.delete(machine); }
}
async function state(t, { runner = new Runner(), persistent = false, limits = {}, stripe = new Stripe() } = {}) {
  const directory = persistent ? await mkdtemp(join(tmpdir(), 'foundation-stopping-')) : null;
  const path = directory ? join(directory, 'state.sqlite') : ':memory:';
  let store;
  const f = { runner, reopen() {
    store?.close(); store = new Store(path, KEY);
    Object.assign(f, { store, ...modules(store), payments: new Payments(store, stripe) });
    f.environments = new Environments({ ...f, limits });
    return f.environments;
  } };
  f.reopen(); f.principals.ensure(USER_A);
  // The owner has registered a payment method, as one who computes must have.
  f.store.db.prepare("INSERT INTO payment_accounts (principal_id,customer_id,subscription_id,status,created_at) VALUES (?,'cus_fixture','sub_fixture','canceled',0)").run(USER_A);
  t.after(async () => { store.close(); if (directory) await rm(directory, { recursive: true, force: true }); });
  return f;
}
const spent = f => f.store.db.prepare('SELECT sum(seconds) n FROM compute_usage').get().n ?? 0;
const keys = (f, id) => f.principals.keys(USER_A).filter(row => row.environment_id === id);

test('停止は先に保存され鍵と新規実行を閉じ、失敗しても計上・保持期限を確定せず再試行する', async t => {
  const f = await state(t, { limits: { concurrent: 1 } }), e = f.environments;
  const row = await e.open(USER_A, { identity: USER_A });
  f.store.db.prepare('UPDATE environments SET started_at=started_at-10000 WHERE resource_id=?').run(row.id);
  const wait = deferred(); f.runner.stopping = () => wait.promise;
  const stopping = e.stop(row), duplicate = e.stop(row);
  assert.equal(e.get(row.id).status, 'stopping'); assert.equal(keys(f, row.id).length, 0);
  assert.equal(e.get(row.id).identity, null); assert.equal(e.get(row.id).expires_at, row.expires_at);
  assert.equal(spent(f), 0); assert.ok(e.usage(USER_A).used_seconds >= 10);
  assert.equal(f.runner.stops.length, 1);
  assert.throws(() => e.run(row, USER_A, { command: ['true'] }), { code: 'environment_stopped' });
  await assert.rejects(e.attach(row, USER_A), { code: 'environment_stopped' });
  await assert.rejects(e.open(USER_A), { code: 'environment_limit' });
  wait.reject(new Error('provider offline'));
  await Promise.all([stopping, duplicate]);
  const failed = e.get(row.id);
  assert.equal(failed.status, 'stopping'); assert.equal(failed.stop_attempts, 1); assert.ok(failed.stop_retry_at > Date.now());
  await e.stop(row); await e.sweep(failed.stop_retry_at - 1);
  assert.equal(f.runner.stops.length, 1); assert.equal(spent(f), 0);
  f.runner.stopping = null;
  await e.sweep(failed.stop_retry_at);
  assert.equal(e.get(row.id).status, 'stopped'); assert.equal(f.runner.machines.has(row.machine), false);
  assert.equal(e.get(row.id).stop_retry_at, null);
  const settled = spent(f); assert.ok(settled >= 10);
  await Promise.all([e.stop(row), e.stop(failed)]); assert.equal(spent(f), settled);
  await e.sweep(e.get(row.id).expires_at); assert.equal(e.get(row.id), undefined);
});

test('削除の失敗も意図を残し、プロセス再起動後の sweep が削除まで完了する', async t => {
  const f = await state(t, { persistent: true }), row = await f.environments.open(USER_A, { identity: USER_A });
  f.runner.stopping = async () => { throw new Error('offline'); };
  await assert.rejects(f.environments.remove(row), { code: 'environment_stopping', status: 503 });
  const failed = f.environments.get(row.id);
  assert.equal(failed.remove_requested, 1); assert.equal(keys(f, row.id).length, 0);
  f.runner = new Runner(f.runner.machines);
  const e = f.reopen();
  assert.equal(e.get(row.id).stop_attempts, 1);
  await e.sweep(failed.stop_retry_at - 1); assert.equal(f.runner.stops.length, 0);
  await e.sweep(failed.stop_retry_at); assert.equal(e.get(row.id), undefined); assert.equal(f.runner.stops.length, 1);
  const settled = spent(f); await e.remove(row); await e.sweep(failed.stop_retry_at + 1000); assert.equal(spent(f), settled);
});

test('停止の途中で再起動してもリース後に回復し、provider で既に消えた機械は成功になる', async t => {
  const f = await state(t, { persistent: true }), row = await f.environments.open(USER_A);
  const retryAt = Date.now() + 120_000;
  f.store.db.prepare("UPDATE environments SET status='stopping',stop_attempts=1,stop_retry_at=? WHERE resource_id=?").run(retryAt, row.id);
  f.runner = new Runner(); f.runner.stopping = async () => { throw Object.assign(new Error('gone'), { gone: true }); };
  const e = f.reopen();
  await e.sweep(retryAt - 1); assert.equal(f.runner.stops.length, 0);
  await e.sweep(retryAt); assert.equal(e.get(row.id).status, 'stopped'); assert.equal(e.get(row.id).stop_attempts, 2);
  const settled = spent(f); await e.stop(row); assert.equal(spent(f), settled);
});

test('重なる sweep と古い試行の完了は、新しい試行の状態や計上を上書きしない', async t => {
  const f = await state(t), e = f.environments, row = await e.open(USER_A), wait = deferred();
  f.runner.stopping = () => wait.promise;
  const first = e.stop(row), claimed = e.get(row.id);
  const next = new Environments({ ...f });
  await next.sweep(claimed.stop_retry_at - 1); assert.equal(f.runner.stops.length, 1);
  f.runner.stopping = null;
  await Promise.all([next.sweep(claimed.stop_retry_at), next.sweep(claimed.stop_retry_at)]);
  assert.equal(e.get(row.id).status, 'stopped'); assert.equal(f.runner.stops.length, 2);
  const settled = spent(f);
  wait.reject(new Error('late failure')); await first;
  assert.equal(e.get(row.id).status, 'stopped'); assert.equal(e.get(row.id).stop_retry_at, null); assert.equal(spent(f), settled);
});

test('繰り返す失敗の待ち時間には上限があり、期限切れでも早く再試行せず別の機械を止める', async t => {
  const f = await state(t), e = f.environments, first = await e.open(USER_A), other = await e.open(USER_A);
  f.runner.stopping = async machine => { if (machine === first.machine) throw new Error('offline'); };
  let now = Date.now() + 3600_000;
  await e.sweep(now);
  assert.equal(e.get(other.id).status, 'stopped'); assert.equal(e.get(first.id).status, 'stopping');
  let previous = 0;
  for (let i = 0; i < 10; i++) {
    const due = e.get(first.id).stop_retry_at, delay = due - now;
    assert.ok(delay >= previous && delay <= 300_000); previous = delay;
    const calls = f.runner.stops.length;
    await e.sweep(due - 1); assert.equal(f.runner.stops.length, calls);
    now = due; await e.sweep(now);
  }
  assert.equal(previous, 300_000);
});

test('runner が無効または別物でも、停止完了とみなさず元の機械を残す', async t => {
  const f = await state(t), e = f.environments, row = await e.open(USER_A);
  e.runner = null; await e.stop(row);
  assert.equal(e.get(row.id).status, 'stopping'); assert.equal(spent(f), 0);
  e.runner = new Runner(); e.runner.name = 'other';
  await e.sweep(e.get(row.id).stop_retry_at); assert.equal(e.runner.stops.length, 0);
  e.runner = f.runner; await e.sweep(e.get(row.id).stop_retry_at);
  assert.equal(e.get(row.id).status, 'stopped');
});

test('起動中の停止は戻ってきた機械を ready に戻さず、鍵を発行しない', async t => {
  const f = await state(t), e = f.environments, started = deferred();
  const start = f.runner.start.bind(f.runner);
  f.runner.start = async options => { await started.promise; return start(options); };
  const opening = e.open(USER_A, { identity: USER_A });
  const row = e.list(USER_A)[0];
  await e.stop(row); assert.equal(e.get(row.id).status, 'stopping'); assert.equal(f.runner.stops.length, 0);
  started.resolve(); await assert.rejects(opening, { code: 'environment_stopped' });
  assert.equal(e.get(row.id), undefined); assert.equal(f.runner.stops.length, 1); assert.equal(keys(f, row.id).length, 0);
});

test('割り当て後の起動失敗でも機械 ID を失わず、停止失敗は sweep で削除する', async t => {
  const f = await state(t), e = f.environments;
  const start = f.runner.start.bind(f.runner);
  f.runner.start = async options => { await start(options); throw new Error('boot failed'); };
  f.runner.stopping = async () => { throw new Error('offline'); };
  await assert.rejects(e.open(USER_A), /boot failed/);
  const row = e.list(USER_A)[0];
  assert.ok(row.machine); assert.equal(row.status, 'stopping'); assert.equal(row.remove_requested, 1);
  f.runner.stopping = null; await e.sweep(row.stop_retry_at); assert.equal(e.get(row.id), undefined);
});

test('停止中に終わるコマンドの値は伏せられ、削除後の完了もエラーにならない', async t => {
  const f = await state(t), e = f.environments;
  for (const remove of [false, true]) {
    const row = await e.open(USER_A), run = deferred();
    e.reveal(row.id, ['secret-value']); f.runner.exec = () => run.promise;
    const command = e.run(row, USER_A, { command: ['echo', 'secret-value'] });
    if (remove) await e.remove(row); else await e.stop(row);
    assert.ok(e.revealed.has(row.id));
    run.resolve(result('secret-value')); const ended = await command.done;
    if (remove) assert.equal(ended, null); else { assert.equal(ended.stdout, '[redacted]'); assert.equal(e.get(row.id).status, 'stopped'); }
    assert.equal(e.revealed.has(row.id), false);
  }
});

test('ID の書き込み中に停止したエンバイロメントは、再び ID や有効な鍵を持たない', async t => {
  const f = await state(t), e = f.environments, row = await e.open(USER_A), write = deferred();
  f.runner.put = () => write.promise;
  const attaching = e.attach(row, USER_A);
  assert.equal(keys(f, row.id).length, 1);
  await e.stop(row); write.resolve(); await assert.rejects(attaching, { code: 'environment_stopped' });
  assert.equal(e.get(row.id).identity, null); assert.equal(keys(f, row.id).length, 0);
});

test('DELETE の停止失敗は503と停止中を返し、principal と全エンバイロメントの再試行を保持する', async t => {
  const runner = new Runner(), f = await fixture(t, { runner });
  const who = (await f.request('/v1/principals', { method: 'POST', data: { name: 'worker' } })).json.principal;
  const first = await f.app.environments.open(who.id, { identity: who.id }), other = await f.app.environments.open(who.id, { identity: who.id });
  runner.stopping = async () => { throw new Error('offline'); };
  const response = await f.request('/v1/principals/' + who.id, { method: 'DELETE', data: {} });
  assert.equal(response.status, 503); assert.ok(f.app.principals.get(who.id));
  for (const row of [first, other]) {
    assert.equal(f.app.environments.get(row.id).status, 'stopping');
    assert.equal(f.app.environments.get(row.id).remove_requested, 1);
  }
  assert.equal(f.app.principals.keys(who.id).length, 0); assert.equal(runner.stops.length, 2);
  const token = f.app.principals.issueKey(who.id).token;
  const deleted = await f.request('/v1/environments/' + first.id, { method: 'DELETE', data: {}, token, anonymous: true });
  assert.equal(deleted.status, 503); assert.equal(deleted.json.error.code, 'environment_stopping');
  const read = await f.request('/v1/environments/' + first.id, { token, anonymous: true });
  assert.equal(read.json.environment.status, 'stopping');
  runner.stopping = null; await f.app.environments.sweep(Date.now() + 10_000);
  assert.equal((await f.request('/v1/principals/' + who.id, { method: 'DELETE', data: {} })).status, 200);
});

test('principal の削除中に開いたエンバイロメントはまとめて消されず、削除後の古い open も拒否する', async t => {
  const runner = new Runner(), f = await fixture(t, { runner });
  const who = (await f.request('/v1/principals', { method: 'POST', data: { name: 'worker' } })).json.principal;
  await f.app.environments.open(who.id);
  const stopping = deferred(), entered = deferred(); runner.stopping = () => { entered.resolve(); return stopping.promise; };
  const deletion = f.request('/v1/principals/' + who.id, { method: 'DELETE', data: {} });
  await entered.promise;
  const concurrent = await f.app.environments.open(who.id);
  stopping.resolve(); const response = await deletion;
  assert.equal(response.status, 409); assert.ok(f.app.principals.get(who.id)); assert.ok(f.app.environments.get(concurrent.id));
  runner.stopping = null;
  assert.equal((await f.request('/v1/principals/' + who.id, { method: 'DELETE', data: {} })).status, 200);
  await assert.rejects(f.app.environments.open(who.id), { code: 'not_found' });
});


test('別プロセスが ID 未確定のエンバイロメントを止めても記録を失わず、遅れて届いた ID を回収できる', async t => {
  const f = await state(t), e = f.environments, started = deferred();
  const start = f.runner.start.bind(f.runner);
  f.runner.start = async options => { await started.promise; return start(options); };
  const opening = e.open(USER_A, { identity: USER_A }), row = e.list(USER_A)[0];
  const other = new Environments({ ...f });
  await assert.rejects(other.remove(row), { code: 'environment_stopping' });
  assert.equal(e.get(row.id).status, 'stopping'); assert.equal(e.get(row.id).machine, null); assert.equal(spent(f), 0);
  assert.equal(f.runner.stops.length, 0);
  started.resolve(); await assert.rejects(opening, { code: 'environment_stopped' });
  assert.equal(e.get(row.id).machine, row.id); assert.equal(keys(f, row.id).length, 0);
  await other.sweep(e.get(row.id).stop_retry_at);
  assert.equal(e.get(row.id), undefined); assert.equal(f.runner.stops.length, 1);
});

test('機械の作成が明確に拒否された場合は使用量を計上せず枠を戻すが、不明な結果は保持する', async t => {
  const f = await state(t), e = f.environments;
  f.runner.start = async () => { throw Object.assign(new Error('rejected'), { notCreated: true }); };
  await assert.rejects(e.open(USER_A), /rejected/);
  assert.equal(e.list(USER_A).length, 0); assert.equal(spent(f), 0);
  f.runner.start = async () => { throw new Error('creation response lost'); };
  await assert.rejects(e.open(USER_A), /creation response lost/);
  const row = e.list(USER_A)[0];
  assert.equal(row.status, 'stopping'); assert.equal(row.machine, null); assert.equal(row.remove_requested, 1);
  await e.sweep(row.stop_retry_at);
  assert.equal(e.get(row.id).status, 'stopping'); assert.equal(spent(f), 0);
});

const meterEvents = f => f.store.db.prepare("SELECT * FROM meter_events WHERE meter='compute' ORDER BY id").all();
function payer(f) {
  f.store.db.prepare('INSERT INTO payment_accounts (principal_id,customer_id,subscription_id,status,created_at) VALUES (?,?,?,?,?) ON CONFLICT(principal_id) DO UPDATE SET customer_id=excluded.customer_id, subscription_id=excluded.subscription_id, status=excluded.status')
    .run(USER_A, 'cus_1', 'sub_1', 'active', Date.now());
}

test('課金する停止も失敗中は未計上のまま保ち、再起動後の停止確定で一度だけ記録する', async t => {
  const fake = fakeStripe(), f = await state(t, { persistent: true, stripe: fake.stripe });
  payer(f);
  const row = await f.environments.open(USER_A, { size: 'medium' });
  f.store.db.prepare('UPDATE environments SET started_at=started_at-10000 WHERE resource_id=?').run(row.id);
  f.runner.stopping = async () => { throw new Error('offline'); };
  await f.environments.stop(row);
  assert.equal(spent(f), 0); assert.equal(meterEvents(f).length, 0);
  await f.payments.send(); assert.equal(fake.meterEvents.size, 0);
  f.runner = new Runner(f.runner.machines);
  const e = f.reopen();
  await e.sweep(e.get(row.id).stop_retry_at);
  const [event] = meterEvents(f);
  assert.ok(event.value >= 20); assert.equal(event.value, spent(f)); assert.equal(event.sent_at, null);
  await Promise.all([e.stop(row), e.stop(row)]);
  f.reopen(); await f.environments.stop(row);
  assert.deepEqual(meterEvents(f), [event]);
  // Stripe may receive the event while its response is lost. The durable identifier is reused after restart.
  const fetcher = fake.stripe.fetcher;
  let responseLost = true;
  fake.stripe.fetcher = async (...args) => {
    const response = await fetcher(...args);
    if (responseLost) { responseLost = false; throw new Error('response lost'); }
    return response;
  };
  await assert.rejects(f.payments.send(), { code: 'payment_unavailable' });
  assert.equal(fake.meterEvents.size, 1); assert.equal(meterEvents(f)[0].sent_at, null);
  f.reopen(); await f.payments.send(); await f.payments.send();
  assert.equal(fake.meterEvents.size, 1); assert.ok(meterEvents(f)[0].sent_at);
  assert.deepEqual(fake.calls.filter(call => call.path === '/v1/billing/meter_events').map(call => call.body.identifier), [event.id, event.id]);
});

test('停止確定のDB書き込みが失敗すると課金イベントも使用量も戻り、復旧時に一度だけ計上する', async t => {
  const f = await state(t, { persistent: true }); payer(f);
  const e = f.environments, row = await e.open(USER_A);
  f.store.db.prepare('UPDATE environments SET started_at=started_at-10000 WHERE resource_id=?').run(row.id);
  const computed = f.payments.computed.bind(f.payments);
  f.payments.computed = (...args) => { computed(...args); throw new Error('settlement interrupted'); };
  await assert.rejects(e.stop(row), /settlement interrupted/);
  assert.equal(f.runner.machines.has(row.machine), false);
  assert.equal(e.get(row.id).status, 'stopping'); assert.equal(spent(f), 0); assert.equal(meterEvents(f).length, 0);
  const retryAt = e.get(row.id).stop_retry_at;
  f.reopen(); await f.environments.sweep(retryAt);
  assert.equal(f.environments.get(row.id).status, 'stopped');
  assert.equal(meterEvents(f).length, 1); assert.equal(meterEvents(f)[0].value, spent(f));
  await f.environments.stop(row); assert.equal(meterEvents(f).length, 1);
});

test('古い停止試行が後から戻っても、引き継いだ停止の課金イベントを重ねない', async t => {
  const f = await state(t); payer(f);
  const e = f.environments, row = await e.open(USER_A), wait = deferred();
  f.store.db.prepare('UPDATE environments SET started_at=started_at-10000 WHERE resource_id=?').run(row.id);
  f.runner.stopping = () => wait.promise;
  const first = e.stop(row), claimed = e.get(row.id);
  const next = new Environments({ ...f });
  f.runner.stopping = null;
  await next.sweep(claimed.stop_retry_at);
  const events = meterEvents(f); assert.equal(events.length, 1);
  wait.resolve(); await first;
  assert.deepEqual(meterEvents(f), events); assert.equal(spent(f), events[0].value);
});

test('操作ごとの grant は準備済みのエンバイロメントにだけ届き、停止中の実行や ID 付与を復活させない', async t => {
  const runner = new Runner(), f = await fixture(t, { runner }), delegate = await f.become('delegate');
  const row = await f.app.environments.open(USER_A), path = '/v1/environments/' + row.id;
  const asDelegate = { token: delegate.token, anonymous: true };
  const run = () => f.request(path + '/commands', { ...asDelegate, method: 'POST', data: { command: ['true'] } });
  const attach = () => f.request(path, { ...asDelegate, method: 'PATCH', data: { identity: USER_A } });
  const remove = () => f.request(path, { ...asDelegate, method: 'DELETE', data: {} });
  const grant = async (relation, object_type = 'resource', object_id = row.id) => {
    const response = await f.request('/v1/relations', { method: 'POST', data: { subject: delegate.id, relation, object_type, object_id } });
    assert.equal(response.status, 201, response.text);
  };
  assert.equal((await run()).status, 401, 'an unrelated key is not yet approved');
  await grant('exec_grant'); assert.equal((await run()).status, 200);
  assert.equal((await attach()).status, 403);
  await grant('identity_grant'); assert.equal((await attach()).status, 403, 'passing the principal also needs its own permission');
  await grant('pass_grant', 'principal', USER_A); assert.equal((await attach()).status, 200);
  assert.equal((await remove()).status, 403);
  await grant('remove_grant');
  runner.stopping = async () => { throw new Error('offline'); };
  const stopping = await remove(); assert.equal(stopping.status, 503); assert.equal(stopping.json.error.code, 'environment_stopping');
  assert.equal(f.app.principals.keys(USER_A).filter(key => key.environment_id === row.id).length, 0);
  assert.equal((await run()).status, 409); assert.equal((await attach()).status, 409);
  runner.stopping = null; await f.app.environments.sweep(f.app.environments.get(row.id).stop_retry_at);
  assert.equal(f.app.environments.get(row.id), undefined);
});
